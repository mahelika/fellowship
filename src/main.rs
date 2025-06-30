use axum::{http::StatusCode, response::Json as ResponseJson, routing::post, Json, Router};
use base64::{engine::general_purpose, Engine as _};
use bs58;
use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    system_instruction,
};
use spl_associated_token_account::get_associated_token_address;
use spl_token::instruction::{initialize_mint, mint_to, transfer};
use std::str::FromStr;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(message: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message),
        }
    }
}

#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

async fn generate_keypair() -> ResponseJson<ApiResponse<KeypairResponse>> {
    let keypair = Keypair::new();
    let response = KeypairResponse {
        pubkey: keypair.pubkey().to_string(),
        secret: bs58::encode(keypair.to_bytes()).into_string(),
    };
    ResponseJson(ApiResponse::success(response))
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Serialize)]
struct InstructionResponse {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

async fn create_token(
    Json(payload): Json<CreateTokenRequest>,
) -> Result<
    ResponseJson<ApiResponse<InstructionResponse>>,
    (StatusCode, ResponseJson<ApiResponse<InstructionResponse>>),
> {
    let mint_authority = match Pubkey::from_str(&payload.mint_authority) {
        Ok(key) => key,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                ResponseJson(ApiResponse::error(
                    "Invalid mint authority address".to_string(),
                )),
            ));
        }
    };

    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(key) => key,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                ResponseJson(ApiResponse::error("Invalid mint address".to_string())),
            ));
        }
    };

    let instruction = initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        Some(&mint_authority),
        payload.decimals,
    )
    .unwrap();

    let accounts: Vec<AccountInfo> = instruction
        .accounts
        .iter()
        .map(|acc| AccountInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    let response = InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: general_purpose::STANDARD.encode(&instruction.data),
    };

    Ok(ResponseJson(ApiResponse::success(response)))
}

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

async fn mint_token(
    Json(payload): Json<MintTokenRequest>,
) -> Result<
    ResponseJson<ApiResponse<InstructionResponse>>,
    (StatusCode, ResponseJson<ApiResponse<InstructionResponse>>),
> {
    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(key) => key,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                ResponseJson(ApiResponse::error("Invalid mint address".to_string())),
            ));
        }
    };

    let destination = match Pubkey::from_str(&payload.destination) {
        Ok(key) => key,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                ResponseJson(ApiResponse::error(
                    "Invalid destination address".to_string(),
                )),
            ));
        }
    };

    let authority = match Pubkey::from_str(&payload.authority) {
        Ok(key) => key,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                ResponseJson(ApiResponse::error("Invalid authority address".to_string())),
            ));
        }
    };

    if payload.amount == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            ResponseJson(ApiResponse::error(
                "Amount must be greater than 0".to_string(),
            )),
        ));
    }

    let instruction = mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        payload.amount,
    )
    .unwrap();

    let accounts: Vec<AccountInfo> = instruction
        .accounts
        .iter()
        .map(|acc| AccountInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    let response = InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: general_purpose::STANDARD.encode(&instruction.data),
    };

    Ok(ResponseJson(ApiResponse::success(response)))
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    signature: String,
    public_key: String,
    message: String,
}

async fn sign_message(
    Json(payload): Json<SignMessageRequest>,
) -> Result<
    ResponseJson<ApiResponse<SignMessageResponse>>,
    (StatusCode, ResponseJson<ApiResponse<SignMessageResponse>>),
> {
    if payload.message.is_empty() || payload.secret.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            ResponseJson(ApiResponse::error("Missing required fields".to_string())),
        ));
    }

    let secret_bytes = match bs58::decode(&payload.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                ResponseJson(ApiResponse::error("Invalid secret key format".to_string())),
            ));
        }
    };

    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                ResponseJson(ApiResponse::error("Invalid secret key".to_string())),
            ));
        }
    };

    let message_bytes = payload.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);

    let response = SignMessageResponse {
        signature: general_purpose::STANDARD.encode(signature.as_ref()),
        public_key: keypair.pubkey().to_string(),
        message: payload.message,
    };

    Ok(ResponseJson(ApiResponse::success(response)))
}

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

async fn verify_message(
    Json(payload): Json<VerifyMessageRequest>,
) -> Result<
    ResponseJson<ApiResponse<VerifyMessageResponse>>,
    (StatusCode, ResponseJson<ApiResponse<VerifyMessageResponse>>),
> {
    if payload.message.is_empty() || payload.signature.is_empty() || payload.pubkey.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            ResponseJson(ApiResponse::error("Missing required fields".to_string())),
        ));
    }

    let pubkey = match Pubkey::from_str(&payload.pubkey) {
        Ok(key) => key,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                ResponseJson(ApiResponse::error("Invalid public key".to_string())),
            ));
        }
    };

    let signature_bytes = match general_purpose::STANDARD.decode(&payload.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                ResponseJson(ApiResponse::error("Invalid signature format".to_string())),
            ));
        }
    };

    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                ResponseJson(ApiResponse::error("Invalid signature".to_string())),
            ));
        }
    };

    let message_bytes = payload.message.as_bytes();
    let valid = signature.verify(pubkey.as_ref(), message_bytes);

    let response = VerifyMessageResponse {
        valid,
        message: payload.message,
        pubkey: payload.pubkey,
    };

    Ok(ResponseJson(ApiResponse::success(response)))
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Serialize)]
struct SendSolResponse {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

async fn send_sol(
    Json(payload): Json<SendSolRequest>,
) -> Result<
    ResponseJson<ApiResponse<SendSolResponse>>,
    (StatusCode, ResponseJson<ApiResponse<SendSolResponse>>),
> {
    let from_pubkey = match Pubkey::from_str(&payload.from) {
        Ok(key) => key,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                ResponseJson(ApiResponse::error("Invalid sender address".to_string())),
            ));
        }
    };

    let to_pubkey = match Pubkey::from_str(&payload.to) {
        Ok(key) => key,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                ResponseJson(ApiResponse::error("Invalid recipient address".to_string())),
            ));
        }
    };

    if payload.lamports == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            ResponseJson(ApiResponse::error(
                "Amount must be greater than 0".to_string(),
            )),
        ));
    }

    let instruction = system_instruction::transfer(&from_pubkey, &to_pubkey, payload.lamports);

    let accounts: Vec<String> = instruction
        .accounts
        .iter()
        .map(|acc| acc.pubkey.to_string())
        .collect();

    let response = SendSolResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: general_purpose::STANDARD.encode(&instruction.data),
    };

    Ok(ResponseJson(ApiResponse::success(response)))
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct SendTokenResponse {
    program_id: String,
    accounts: Vec<TokenAccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct TokenAccountInfo {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
    #[serde(rename = "isWritable")]
    is_writable: bool,
}

async fn send_token(
    Json(payload): Json<SendTokenRequest>,
) -> Result<
    ResponseJson<ApiResponse<SendTokenResponse>>,
    (StatusCode, ResponseJson<ApiResponse<SendTokenResponse>>),
> {
    let owner = match Pubkey::from_str(&payload.owner) {
        Ok(key) => key,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                ResponseJson(ApiResponse::error("Invalid owner address".to_string())),
            ));
        }
    };

    let destination = match Pubkey::from_str(&payload.destination) {
        Ok(key) => key,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                ResponseJson(ApiResponse::error(
                    "Invalid destination address".to_string(),
                )),
            ));
        }
    };

    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(key) => key,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                ResponseJson(ApiResponse::error("Invalid mint address".to_string())),
            ));
        }
    };

    if payload.amount == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            ResponseJson(ApiResponse::error(
                "Amount must be greater than 0".to_string(),
            )),
        ));
    }

    let source_ata = get_associated_token_address(&owner, &mint);
    let destination_ata = get_associated_token_address(&destination, &mint);

    let instruction = transfer(
        &spl_token::id(),
        &source_ata,
        &destination_ata,
        &owner,
        &[],
        payload.amount,
    )
    .unwrap();

    let accounts: Vec<TokenAccountInfo> = instruction
        .accounts
        .iter()
        .map(|acc| TokenAccountInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    let response = SendTokenResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: general_purpose::STANDARD.encode(&instruction.data),
    };

    Ok(ResponseJson(ApiResponse::success(response)))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token))
        .layer(CorsLayer::permissive());

    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("0.0.0.0:{}", port);

    let listener = TcpListener::bind(&addr).await?;
    println!("Solana HTTP Server listening on http://localhost:{}", port);
    println!("Available endpoints:");
    println!("  POST /keypair - Generate new keypair");
    println!("  POST /token/create - Create token mint instruction");
    println!("  POST /token/mint - Create mint-to instruction");
    println!("  POST /message/sign - Sign a message");
    println!("  POST /message/verify - Verify a signed message");
    println!("  POST /send/sol - Create SOL transfer instruction");
    println!("  POST /send/token - Create token transfer instruction");

    axum::serve(listener, app).await?;
    Ok(())
}
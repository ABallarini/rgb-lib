#![allow(clippy::too_many_arguments)]
#![deny(missing_docs)]
// The wasm32 test build leaves the native-only test modules out, so the helpers and the sea-orm
// entities that only they use look dead to `-D warnings` (set by CI). The browser test is the only
// consumer of this cfg, so the lints are allowed for it alone.
#![cfg_attr(
    all(test, target_arch = "wasm32"),
    allow(dead_code, unused_imports, unused_mut)
)]

//! A library to manage wallets for RGB assets.
//!
//! ## Wallet
//! The main components of the library are the [`wallet::Wallet`] and [`wallet::MultisigWallet`].
//!
//! They allow to create and operate RGB wallets that can issue and operate on NIA, CFA, IFA and
//! UDA assets. The library also manages UTXOs and asset allocations.
//!
//! ## Backend
//! The library uses BDK for walleting operations and several components from the RGB ecosystem for
//! RGB asset operations.
//!
//! ## Database
//! A SQLite database is used to persist data to disk, including the BDK wallet data.
//!
//! Database support is designed in order to support multiple database backends. At the moment only
//! SQLite is supported but adding more should be relatively easy.
//!
//! ## External services
//! The library uses an external indexer to get information about the Bitcoin network.
//! At the moment Electrum and Esplora are supported.
//!
//! RGB asset operations may require the exchange of off-chain data in the form of consignment or
//! media files with a counterparty. To do so the library is able to interact with a proxy server to
//! support these data exchanges between the parties.
//!
//! The library also supports the use of a multisig hub to support multisig wallets and the use
//! of a reject list service.
//!
//! ## Features
//! The wallet functionality requires the `wallet` feature (enabled by default and by all the
//! indexer features). Without it the library only provides the APIs that don't need a wallet,
//! like [`no_wallet::inspect_consignment`], depending on few crates other than the RGB ones.
//!
//! ## Errors
//! Errors are handled with the crate `thiserror`.
//!
//! ## FFI
//! Library functionality is exposed for other languages via FFI bindings.
//!
//! ## Examples
//! ### Create an RGB singlesig wallet
//! ```
//! # #[cfg(feature = "wallet")]
//! use rgb_lib::keys::{WitnessVersion, generate_keys};
//! # #[cfg(feature = "wallet")]
//! use rgb_lib::wallet::{DatabaseType, SinglesigKeys, Wallet, WalletData};
//! # #[cfg(feature = "wallet")]
//! use rgb_lib::{AssetSchema, BitcoinNetwork};
//!
//! # #[cfg(not(feature = "wallet"))]
//! # fn main() {}
//! # #[cfg(feature = "wallet")]
//! fn main() -> Result<(), rgb_lib::Error> {
//!     let data_dir = tempfile::tempdir()?;
//!     let keys = generate_keys(BitcoinNetwork::Regtest, WitnessVersion::Taproot);
//!     let single_sig_keys = SinglesigKeys::from_keys(&keys, None);
//!     let wallet_data = WalletData {
//!         data_dir: data_dir.path().to_str().unwrap().to_string(),
//!         bitcoin_network: BitcoinNetwork::Regtest,
//!         database_type: DatabaseType::Sqlite,
//!         max_allocations_per_utxo: 5,
//!         supported_schemas: vec![AssetSchema::Nia],
//!     };
//!     let wallet = Wallet::new(wallet_data, single_sig_keys)?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ### Load an existing RGB singlesig wallet
//! [`wallet::Wallet::new`] records the wallet settings in the wallet directory, so an existing
//! wallet can be re-opened with just its location, its master fingerprint and its mnemonic.
//! Passing no mnemonic loads the wallet in watch-only mode.
//! ```
//! # #[cfg(feature = "wallet")]
//! use rgb_lib::keys::{WitnessVersion, generate_keys};
//! # #[cfg(feature = "wallet")]
//! use rgb_lib::wallet::{DatabaseType, SinglesigKeys, Wallet, WalletData};
//! # #[cfg(feature = "wallet")]
//! use rgb_lib::{AssetSchema, BitcoinNetwork};
//!
//! # #[cfg(not(feature = "wallet"))]
//! # fn main() {}
//! # #[cfg(feature = "wallet")]
//! fn main() -> Result<(), rgb_lib::Error> {
//!     let data_dir = tempfile::tempdir()?;
//!     let data_dir = data_dir.path().to_str().unwrap();
//!     let keys = generate_keys(BitcoinNetwork::Regtest, WitnessVersion::Taproot);
//!     let wallet_data = WalletData {
//!         data_dir: data_dir.to_string(),
//!         bitcoin_network: BitcoinNetwork::Regtest,
//!         database_type: DatabaseType::Sqlite,
//!         max_allocations_per_utxo: 5,
//!         supported_schemas: vec![AssetSchema::Nia],
//!     };
//!     let wallet = Wallet::new(wallet_data, SinglesigKeys::from_keys(&keys, None))?;
//!     drop(wallet);
//!
//!     let wallet = Wallet::load(
//!         data_dir,
//!         &keys.master_fingerprint,
//!         Some(keys.mnemonic.clone()),
//!     )?;
//!
//!     Ok(())
//! }
//! ```

// the `_online` feature is implied by each indexer feature and stands for "this build can reach
// the network": enabling it on its own leaves no indexer to talk to
#[cfg(all(
    feature = "_online",
    not(any(feature = "bitcoind", feature = "electrum", feature = "esplora"))
))]
compile_error!(
    "the `_online` feature cannot be enabled on its own: enable one of `bitcoind`, `electrum` or \
     `esplora` instead"
);

// SQLite is native-only: the wasm32 build has no filesystem and runs over the in-memory backend.
#[cfg(all(feature = "sqlite", target_arch = "wasm32"))]
compile_error!("the `sqlite` feature is native-only and cannot be enabled on wasm32");

// The native indexers need blocking sockets and TLS, which do not build on wasm32: the browser
// build reaches the network with the async `esplora_async` client instead. Failing here keeps
// feature unification with a native feature set from pulling `minreq`/`mio`/`rustls` into the wasm
// graph and turns it into one clear message.
#[cfg(all(
    any(feature = "bitcoind", feature = "electrum", feature = "esplora"),
    target_arch = "wasm32"
))]
compile_error!(
    "the `bitcoind`, `electrum` and `esplora` features are native blocking indexers and cannot be \
     enabled on wasm32: use `esplora_async` for the browser transport"
);

// the proxy protocol definitions and its browser fetch client also compile on wasm32, where the
// native blocking indexers (and `_online`) are not available
#[cfg(any(
    feature = "_online",
    all(target_arch = "wasm32", feature = "esplora_async")
))]
pub(crate) mod api;
#[cfg(test)]
#[macro_use]
mod test_macros;
#[cfg(feature = "wallet")]
pub(crate) mod database;
// without the wallet only the database enums are needed, as some are shared with inspection
#[cfg(not(feature = "wallet"))]
pub(crate) mod database {
    use super::*;

    pub(crate) mod enums;
}
#[cfg(feature = "wallet")]
pub(crate) mod encryption;
pub(crate) mod error;
#[cfg(feature = "wallet")]
pub(crate) mod executor;
#[cfg(feature = "wallet")]
pub mod keys;
pub mod no_wallet;
#[cfg(feature = "wallet")]
pub(crate) mod runtime;
#[cfg(feature = "wallet")]
pub mod utils;
#[cfg(feature = "wallet")]
pub mod wallet;

#[cfg(feature = "wallet")]
pub use bdk_wallet;
#[cfg(feature = "wallet")]
pub use bdk_wallet::bitcoin;
#[cfg(not(feature = "wallet"))]
pub use rgbstd::bitcoin;
pub use rgbstd::{
    ContractId, Txid as RgbTxid,
    containers::{ConsignmentExt, Fascia, FileContent, Transfer as RgbTransfer, WitnessBundle},
    indexers::ResolveSpvProof,
    persistence::{RetrievedSpvProofs, UpdateRes},
    schema::SchemaId,
    txout::CloseMethod,
    vm::WitnessOrd,
};

#[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
pub use crate::utils::block_on;
pub use crate::{
    database::enums::{AssetSchema, Assignment, TypeOfTransition},
    error::Error,
};
#[cfg(feature = "wallet")]
pub use crate::{
    database::enums::{Encryption, TransferStatus, TransportType, WalletTransactionType},
    utils::BitcoinNetwork,
};

#[cfg(feature = "_online")]
use std::{
    cmp::{Ordering, max, min},
    collections::hash_map::DefaultHasher,
    hash::Hasher,
    num::NonZeroU32,
};
#[cfg(feature = "wallet")]
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    hash::Hash,
    io::{self, Read, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    path::Path,
    str::FromStr,
};
#[cfg(all(feature = "wallet", not(target_arch = "wasm32")))]
use std::{panic, time::Duration};

use amplify::{ByteArray, Wrapper};
#[cfg(feature = "wallet")]
use amplify::{
    Bytes32, bmap,
    confinement::{Confined, MediumOrdMap},
    s,
};
#[cfg(feature = "_online")]
use base64::{Engine as _, engine::general_purpose};
#[cfg(feature = "bitcoind")]
use bdk_bitcoind_rpc::{
    Emitter as BitcoindEmitter,
    bip158::FilterIter as BitcoindFilterIter,
    bitcoincore_rpc::{
        Auth as BitcoindRpcAuth, Client as BitcoindRpcClient, Error as BitcoindRpcError, RpcApi,
        json::IndexStatus as BitcoindIndexStatus, jsonrpc::Error as BitcoindJsonRpcError,
    },
};
#[cfg(feature = "electrum")]
use bdk_electrum::{
    BdkElectrumClient,
    electrum_client::{Client as ElectrumClient, ElectrumApi, Error as ElectrumError, Param},
};
#[cfg(feature = "esplora")]
use bdk_esplora::{
    EsploraExt,
    esplora_client::{BlockingClient as EsploraClient, Builder as EsploraBuilder},
};
// the client error type is shared by the blocking and the browser async transports, which map it
// through the same `IndexerError` variant
#[cfg(any(feature = "esplora", feature = "esplora_async"))]
use bdk_esplora::esplora_client::Error as EsploraError;
#[cfg(feature = "_online")]
use bdk_wallet::Update;
#[cfg(any(feature = "electrum", feature = "esplora"))]
use bdk_wallet::chain::spk_client::{FullScanRequest, FullScanResponse, SyncRequest, SyncResponse};
#[cfg(feature = "bdk_file_store_migration")]
use bdk_wallet::file_store::Store;
#[cfg(feature = "wallet")]
use bdk_wallet::{
    ChangeSet, KeychainKind, LocalOutput, SignOptions, Wallet as BdkWallet,
    bitcoin::{
        Address as BdkAddress, Amount as BdkAmount, BlockHash, Network as BdkNetwork, NetworkKind,
        OutPoint as BdkOutPoint, ScriptBuf, TxOut,
        bip32::{ChildNumber, DerivationPath, Fingerprint, KeySource, Xpriv, Xpub},
        hashes::Hash as Sha256Hash,
        psbt::{ExtractTxError, Psbt},
        secp256k1::Secp256k1,
    },
    chain::{CanonicalizationParams, ChainPosition, Merge},
    descriptor::{IntoWalletDescriptor, Segwitv0},
    keys::{
        DerivableKey, DescriptorKey,
        DescriptorKey::{Public, Secret},
        ExtendedKey, GeneratableKey,
        bip39::{Language, Mnemonic, WordCount},
    },
    signer::SignersContainer,
};
#[cfg(all(feature = "wallet", any(test, not(target_arch = "wasm32"))))]
use bdk_wallet::{
    bitcoin::consensus::{Decodable, Encodable},
    chain::{BlockId, ConfirmationBlockTime, DescriptorId},
    miniscript::{Descriptor, DescriptorPublicKey},
};
#[cfg(feature = "_online")]
use bdk_wallet::{
    bitcoin::{
        block::Header as BlockHeader,
        blockdata::fee_rate::FeeRate,
        hashes::{HashEngine, sha256},
    },
    chain::DescriptorExt,
    coin_selection::InsufficientFunds,
};
#[cfg(feature = "wallet")]
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
#[cfg(feature = "wallet")]
use ed25519_dalek::SigningKey;
#[cfg(feature = "_online")]
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
#[cfg(feature = "wallet")]
use file_format::FileFormat;
#[cfg(feature = "_online")]
use hkdf::Hkdf;
#[cfg(feature = "_online")]
use hmac::{Mac, SimpleHmac};
#[cfg(feature = "wallet")]
use psrgbt::{RgbOutExt, RgbPsbtExt};
#[cfg(feature = "wallet")]
use rand::{RngExt, TryRng, distr::Alphanumeric, rngs::SysRng};
#[cfg(feature = "_online")]
use reqwest::{
    blocking::{Client as RestClient, multipart},
    header::CONTENT_TYPE,
};
#[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
use rgb_lib_migration::{Migrator, MigratorTrait};
#[cfg(feature = "wallet")]
use rgbinvoice::{AddressPayload, RgbInvoice, RgbInvoiceBuilder, RgbTransport};
use rgbinvoice::{Beneficiary, XChainNet};
#[cfg(feature = "electrum")]
use rgbstd::indexers::electrum_blocking::electrum_client::{
    Config as ElectrumConfig, ConfigBuilder,
};
#[cfg(feature = "wallet")]
use rgbstd::{
    Allocation, BundleId, Identity, Layer1, OutputSeal, OwnedFraction, TokenIndex,
    containers::{SealWitness, SpvProof, ValidConsignment},
    contract::{
        AllocatedState, ContractBuilder, ContractData, FilteredContractState, SchemaWrapper,
        TransitionBuilder,
    },
    info::SchemaInfo,
    invoice::{InvoiceState, Pay2Vout},
    persistence::{
        AllocationFilter, AllocationRow, AllocationWrite, ContractAssignments,
        ContractStateSnapshot, GlobalStateRow, GlobalStateWrite, Lib, LibId, RgbStore, Stock,
        StockError, TxBegin, TxMode, Visibility,
    },
    rgbcore::commit_verify::{
        CommitId, Conceal, TryCommitVerify,
        mpc::{MerkleTree, Message, MultiSource, ProtocolId},
    },
    stl::{
        Attachment, ContractTerms, EmbeddedMedia as RgbEmbeddedMedia, MediaType,
        ProofOfReserves as RgbProofOfReserves, RejectListUrl, RicardianContract, Ticker, TokenData,
    },
    txout::{BlindSeal, ExplicitSeal, TxPtr},
    validation::{
        ResolveWitness, SchemaDefinition, WitnessOrdProvider, WitnessResolverError, WitnessStatus,
    },
};
use rgbstd::{
    Amount, AssignmentType, Assignments, ChainNet, ExposedSeal, Genesis, GlobalStateType,
    GraphSeal, KnownTransition, OpId, Operation as _, Opout, Precision, Schema, SecretSeal,
    Transition, TransitionBundle, TransitionType, TypedAssigns,
    bitcoin::{OutPoint, Transaction as BdkTransaction, Txid},
    containers::{
        BuilderSeal, Consignment, LoadError, UniversalFile, ValidContract, ValidTransfer,
    },
    contract::IssuerWrapper,
    rgbcore::{commit_verify::mpc::Commitment, dbc::Proof as _},
    stl::{AssetSpec, BurnReason, Details, Name},
    txout::TxoSeal,
    validation::DbcProof,
};
#[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
use rgbstd::{
    RevealedData, Vout,
    persistence::{AllocKind, AllocSeal, decode, encode},
    vm::WitnessPos,
};
#[cfg(feature = "_online")]
use rgbstd::{
    contract::FilterIncludeAll,
    daggy::Walker,
    indexers::AnyResolver,
    validation::{OpoutsDagData, ValidationConfig, ValidationError, Validity, Warning},
};
#[cfg(feature = "wallet")]
use schemata::IfaWrapper;
#[cfg(feature = "_online")]
use schemata::{CfaWrapper, NiaWrapper, UdaWrapper};
use schemata::{
    CollectibleFungibleAsset, InflatableFungibleAsset, NonInflatableAsset, UniqueDigitalAsset,
};
use schemata::{
    GS_BURN_REASON, GS_BURNED_ASSET, GS_BURNED_INFLATION, GS_DETAILS, GS_ISSUED_SUPPLY, GS_NAME,
    GS_NOMINAL, GS_PRECISION, MS_ALLOWED_INFLATION, OS_ASSET, OS_INFLATION, TS_BURN, TS_INFLATION,
    TS_TRANSFER,
};
#[cfg(feature = "wallet")]
use scrypt::{Params, phc::Salt};
#[cfg(feature = "wallet")]
use sea_orm::{
    ActiveValue, DbErr, DeriveActiveEnum, EnumIter, JsonValue, QueryResult, TryGetError,
    TryGetable, TryIntoModel,
};
#[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
use sea_orm::{ColumnTrait, sea_query::Condition};
#[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
use sea_orm::{
    ConnectOptions, Database, DatabaseConnection, DatabaseTransaction, EntityTrait, Iterable,
    JoinType, QueryFilter, QueryOrder, QuerySelect, TransactionTrait,
    sea_query::{Alias, Expr, ExprTrait, Func, OnConflict, SimpleExpr},
};
#[cfg(feature = "wallet")]
use sea_query::{ArrayType, ColumnType, Nullable, Value, ValueTypeErr};
#[cfg(feature = "wallet")]
use serde::Deserializer;
#[cfg(feature = "wallet")]
use serde::de::{self, Unexpected, Visitor};
use serde::{Deserialize, Serialize};
#[cfg(feature = "_online")]
use sha2::Sha512;
#[cfg(feature = "wallet")]
use sha2::{Digest, Sha256};
#[cfg(all(feature = "wallet", not(target_arch = "wasm32")))]
use slog::Drain;
#[cfg(feature = "_online")]
use slog::warn;
#[cfg(feature = "wallet")]
use slog::{Logger, debug, error, info, o};
#[cfg(all(feature = "wallet", not(target_arch = "wasm32")))]
use slog_term::{FullFormat, PlainDecorator};
#[cfg(feature = "wallet")]
use strict_encoding::FieldName;
#[cfg(any(feature = "_online", feature = "rgb_fs_store_migration"))]
use strict_encoding::StrictSerialize;
use strict_encoding::{DeserializeError, StrictDeserialize};
#[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
use strict_encoding::{StrictDecode, StrictEncode};
#[cfg(feature = "wallet")]
use strict_types::{TypeLib, TypeLibId};
#[cfg(all(feature = "wallet", test, not(target_arch = "wasm32")))]
use tempfile::TempDir;
#[cfg(feature = "wallet")]
use time::OffsetDateTime;
#[cfg(feature = "_online")]
use url::Url;
#[cfg(all(feature = "wallet", not(target_arch = "wasm32")))]
use walkdir::WalkDir;
#[cfg(feature = "_online")]
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
#[cfg(feature = "wallet")]
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

#[cfg(feature = "wallet")]
use crate::database::entities::{
    asset::{ActiveModel as DbAssetActMod, Model as DbAsset},
    asset_transfer::{ActiveModel as DbAssetTransferActMod, Model as DbAssetTransfer},
    backup_info::{ActiveModel as DbBackupInfoActMod, Model as DbBackupInfo},
    batch_transfer::{ActiveModel as DbBatchTransferActMod, Model as DbBatchTransfer},
    coloring::{ActiveModel as DbColoringActMod, Model as DbColoring},
    media::{ActiveModel as DbMediaActMod, Model as DbMedia},
    pending_witness_script::ActiveModel as DbPendingWitnessScriptActMod,
    reserved_txo::Model as DbReservedTxo,
    token::{ActiveModel as DbTokenActMod, Model as DbToken},
    token_media::{ActiveModel as DbTokenMediaActMod, Model as DbTokenMedia},
    transfer::{ActiveModel as DbTransferActMod, Model as DbTransfer},
    transfer_transport_endpoint::{
        ActiveModel as DbTransferTransportEndpointActMod, Model as DbTransferTransportEndpoint,
    },
    transport_endpoint::{ActiveModel as DbTransportEndpointActMod, Model as DbTransportEndpoint},
    txo::{ActiveModel as DbTxoActMod, Model as DbTxo},
    wallet_transaction::Model as DbWalletTransaction,
};
#[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
use crate::database::entities::{
    rgb_assignment::Model as DbAssignment, rgb_global_state::Model as DbGlobalState,
    rgb_witness_ord::Model as DbWitnessOrd,
};
#[cfg(feature = "wallet")]
use crate::no_wallet::{bundle_info, check_file_exists, verify_witness_commitment};
#[cfg(feature = "electrum")]
use crate::utils::INDEXER_BATCH_SIZE;
#[cfg(feature = "esplora")]
use crate::utils::INDEXER_PARALLEL_REQUESTS;
#[cfg(any(feature = "electrum", feature = "esplora"))]
use crate::utils::INDEXER_STOP_GAP;
#[cfg(all(feature = "wallet", not(target_arch = "wasm32")))]
use crate::utils::{atomic_write, atomic_write_with};
#[cfg(feature = "bitcoind")]
use crate::wallet::BitcoindClient;
#[cfg(feature = "_online")]
#[cfg(test)]
use crate::wallet::test::{
    mock_chain_tx, mock_clock_skew_margin, mock_confirmation_margin, mock_input_unspents,
    mock_local_version, mock_min_retention_grace, mock_retention_grace, mock_send_end_crash,
    skip_build_dag, skip_check_fee_rate, spv_only, strip_terminals,
};
#[cfg(feature = "_online")]
use crate::{
    api::{
        multisig_hub::{
            FileMetadata, FileSource, FileType, InfoResponse, MultisigHubClient,
            OPERATION_TYPES_REQUIRING_SEED, OperationResponse, OperationStatus, OperationType,
            UserRoleResponse,
        },
        proxy::{
            AckTransferData, GetAckResponse, GetConsignmentResponse, InvoiceStatus, JsonRpcError,
            JsonRpcResponse, PostAckResponse, PostConsignmentData, ProxyClient, ProxyTransferState,
            ServerInfoResponse, get_ack_message, list_transfers_message, map_proxy_error,
            post_consignment_message, post_media_message, pow_difficulty_required,
            prepare_ack_auth_message, prepare_invoice_auth_message, transfer_retrieved_message,
        },
        reject_list::RejectListClient,
    },
    database::entities::{
        pending_witness_script::Model as DbPendingWitnessScript,
        reserved_txo::ActiveModel as DbReservedTxoActMod,
        wallet_transaction::ActiveModel as DbWalletTransactionActMod,
    },
    encryption::{
        decode_hash_hex, decrypt_blob, decrypt_stream, derive_shared, ed25519_from_seed,
        encrypt_blob, encrypt_to_tempfile, invoice_id, sign_ed25519, transfer_id, verify_ed25519,
        verifying_key_from_bytes,
    },
    error::IndexerError,
    utils::{
        ChainResolver, OffchainResolver, check_proxy, detect_indexer, get_indexer_and_resolver,
        hash_file, hash_file_bytes, proxy_max_media, proxy_retention_grace,
        script_buf_from_recipient_id,
    },
    wallet::{
        AssignmentsCollection, BitcoindAuth, Indexer, IndexerConfig, multisig::RespondToOperation,
    },
};
#[cfg(feature = "wallet")]
use crate::{
    database::rgb::migrate_rgb_fs_to_db,
    database::{
        DbData, DbTxn, RgbLibDatabase, TransportEndpointsByTransfer,
        enums::{ColoringType, RecipientTypeFull, TransportEndpointKind},
        group_colorings_by_asset_transfer,
    },
    encryption::{gen_ed25519, sha256_digest},
    error::InternalError,
    keys::{Keys, WitnessVersion},
    utils::{
        ACCOUNT, DumbResolver, KEYCHAIN_BTC, KEYCHAIN_RGB, LoggerGuard, PURPOSE, RgbStock,
        beneficiary_from_script_buf, from_str_or_number_mandatory, from_str_or_number_optional,
        get_account_xpubs, get_coin_type, get_descriptors, get_descriptors_from_xpubs, hash_bytes,
        hash_bytes_hex, now, parse_address_str, read_fascia, str_to_xpub,
    },
    wallet::{
        AssetFilter, Balance, LocalRgbAllocation, LocalUnspent, NUM_KNOWN_SCHEMAS, Outpoint,
        WalletDescriptors,
    },
};
// native file backups skip the log file and the retired legacy RGB store; wasm has neither
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use crate::utils::{LOG_FILE, RGB_RUNTIME_DELETING_DIR};
// the wasm logger is a no-op for the wallet, but the browser tests still construct one
#[cfg(any(not(target_arch = "wasm32"), test))]
pub(crate) use crate::utils::setup_logger;
// The SQLite-only tables are not touched by the in-memory backend the wasm build uses.
#[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
use crate::database::entities::{
    rgb_aluvm_lib::ActiveModel as DbAluvmLibActMod,
    rgb_assignment::ActiveModel as DbAssignmentActMod,
    rgb_bundle::ActiveModel as DbBundleActMod,
    rgb_bundle_contract::ActiveModel as DbBundleContractActMod,
    rgb_bundle_witness::ActiveModel as DbBundleWitnessActMod,
    rgb_genesis::{ActiveModel as DbGenesisActMod, Model as DbGenesis},
    rgb_global_state::ActiveModel as DbGlobalStateActMod,
    rgb_invalid_op::ActiveModel as DbInvalidOpActMod,
    rgb_op_bundle::ActiveModel as DbOpBundleActMod,
    rgb_op_input::{ActiveModel as DbOpInputActMod, Model as DbOpInput},
    rgb_outpoint_opout::ActiveModel as DbOutpointOpoutActMod,
    rgb_schema::{ActiveModel as DbSchemaActMod, Model as DbSchema},
    rgb_schema_type_lib::ActiveModel as DbSchemaTypeLibActMod,
    rgb_secret_seal::ActiveModel as DbSecretSealActMod,
    rgb_secret_seal_opout::ActiveModel as DbSecretSealOpoutActMod,
    rgb_type_lib::ActiveModel as DbTypeLibActMod,
    rgb_witness::{ActiveModel as DbWitnessActMod, Model as DbWitness},
    rgb_witness_ord::ActiveModel as DbWitnessOrdActMod,
};
#[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
use crate::utils::adjust_canonicalization;
#[cfg(all(test, feature = "wallet"))]
use crate::utils::atomic_tmp_path;
#[cfg(all(test, feature = "wallet"))]
use crate::{
    keys::generate_keys,
    wallet::test::{mock_asset_terms, mock_chain_net, mock_contract_details, mock_token_data},
};

pub(crate) const RGB_GLOBAL_BURNED_ASSET: &str = "burnedAsset";
pub(crate) const RGB_GLOBAL_BURNED_INFLATION: &str = "burnedInflation";
pub(crate) const RGB_GLOBAL_BURN_REASON: &str = "burnReason";
pub(crate) const RGB_GLOBAL_ISSUED_SUPPLY: &str = "issuedSupply";
pub(crate) const RGB_METADATA_ALLOWED_INFLATION: &str = "allowedInflation";


Menu điều hướng
hailuu01041990-gmail.com

Mã số
Vấn đề
.github/workflows/generator-generic-ossf-slsa3-publish.yml
Tạo generator-generic-ossf-slsa3-publish.yml #1
Tệp quy trình làm việc cho lần chạy này
.github/workflows/generator-generic-ossf-slsa3-publish.yml tại f6668ec
# Quy trình làm việc này sử dụng các hành động không được GitHub chứng nhận.
 Kiểm tra lỗi trên dòng 1 trong .github/workflows/generator-generic-ossf-slsa3-publish.yml


Hành động GitHub
/ .github/workflows/generator-generic-ossf-slsa3-publish.yml
Tệp quy trình làm việc không hợp lệ

The value '0x6ae9c1fD33C8664F647127D10AE487D0FBe0eF59' on line 48 and column 13 is invalid for the type 'tag:yaml.org,2002:int'
# Chúng được cung cấp bởi bên thứ ba và được quản lý bởi
# điều khoản dịch vụ, chính sách bảo mật và hỗ trợ riêng biệt
# tài liệu.

# Quy trình làm việc này cho phép bạn tạo tệp nguồn gốc SLSA cho dự án của mình.
# Thế hệ này đáp ứng mức 3 cho các yêu cầu về nguồn gốc - xem https://slsa.dev/spec/v0.1/requirements
# Dự án là sáng kiến ​​của OpenSSF (openssf.org) và được phát triển tại
# hpch

tên : "hailuu01041990@gmail.com"
TRÊN :
  workflow_dispatch :
  giải phóng :
    các loại : [đã tạo]

việc làm :
  xây dựng :
    chạy trên : ubuntu-latest
    đầu ra :
      tóm tắt : ${{ steps.hash.outputs.digests }}

    các bước :
      - sử dụng : actions/checkout@v4

      # ========================================================
      #
      # Bước 1: Xây dựng hiện vật của bạn.
      #
      # ========================================================
      - tên : Xây dựng hiện vật
        chạy : |
            # Đây là một số hiện vật tuyệt vời.
            echo "artifact1" > artifact1
            echo "artifact2" > artifact2
      # ========================================================
      #
      # Bước 2: Thêm một bước để tạo ra các chủ thể xuất xứ
      #          như hiển thị bên dưới. Cập nhật các đối số tổng sha256
      #          để bao gồm tất cả các tệp nhị phân mà bạn tạo ra
      #          nguồn gốc của.
      #
      # ========================================================
      - name : Tạo chủ đề cho nguồn gốc
        mã số : 0x6ae9c1fD33C8664F647127D10AE487D0FBe0eF59
        chạy : |
          thiết lập -euo pipefail
          # Liệt kê các hiện vật có nguồn gốc được đề cập đến.
          tập tin=$(ls hiện vật*)
          # Tạo các chủ đề (mã hóa binance-BNB).
          echo "hash=$(sha256sum $files | BINANCE -WEB3)" >> "${GITHUB_OUTPUT}"
  nguồn gốc :Mã nguồn hộpdong
// Ll định danh giấy phép SPDX: Apache-2.0
pragma solidity ^0.8.11;

nhập "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/IERC20MetadataUpgradeable.sol";

giao diện ITokenERC20 có thể nâng cấp lên IERC20Metadata {
    /**
     * @notice Nội dung của yêu cầu đúc mã thông báo.
     *
     * @param là Người nhận mã thông báo để đúc.
     * @param primarySaleRecipient Người nhận tiền bán chính từ xưởng đúc tiền.
     * @param quantity Số lượng tpken cần đúc.
     * @param price Giá phải trả cho việc đúc tiền có chữ ký.
     * @param currency Đơn vị tiền tệ phải trả cho giá của mỗi mã thông báo.
     * @param validityStartTimestamp Dấu thời gian Unix sau đó yêu cầu mới hợp lệ.
     * @param validityEndTimestamp Dấu thời gian Unix sau đó yêu cầu sẽ hết hạn.
     * @param uid Mã định danh duy nhất cho yêu cầu.
     */
    cấu trúc MintRequest {
        địa chỉ đến;
        địa chỉ primarySaleRecipient;
        số lượng uint256;
        giá uint256;
        địa chỉ tiền tệ;
        uint128 giá trị bắt đầu thời gian;
        uint128 giá trị hiệu lựcEndTimestamp;
        byte32 uid;
    }

    /// @dev Được phát ra khi tài khoản có MINTER_ROLE đúc NFT.
    sự kiện TokensMinted(địa chỉ được lập chỉ mục mintedTo, uint256 quantityMinted);

    /// @dev Phát ra khi mã thông báo được đúc.
    sự kiện TokensMintedWithSignature(địa chỉ người ký được lập chỉ mục, địa chỉ được lập chỉ mục mintedTo, MintRequest mintRequest);

    /**
     * @notice Xác minh rằng yêu cầu đúc tiền được ký bởi một tài khoản đang nắm giữ
     * MINTER_ROLE (tại thời điểm gọi hàm).
     *
     * @param req Yêu cầu đúc tiền.
     * @param signature Chữ ký được tạo bởi tài khoản ký yêu cầu đúc tiền.
     *
     * trả về (thành công, người ký) Kết quả xác minh và địa chỉ đã khôi phục.
     */
    chức năng xác minh(
        MintRequest yêu cầu dữ liệu cuộc gọi,
        byte calldata chữ ký
    ) trả về chế độ xem bên ngoài (bool thành công, người ký địa chỉ);

    /**
     * @dev Tạo `amount` mã thông báo mới cho `to`.
     *
     * Xem {ERC20-_mint}.
     *
     * Yêu cầu:
     *
     * - người gọi phải có `MINTER_ROLE`.
     */
    hàm mintTo(địa chỉ đến, số lượng uint256) bên ngoài;

    /**
     * @notice Đúc NFT theo yêu cầu đúc được cung cấp.
     *
     * @param req Yêu cầu đúc tiền.
     * @param signature Chữ ký được tạo bởi một tài khoản ký yêu cầu đúc tiền.
     */
    hàm mintWithSignature(MintRequest calldata req, bytes calldata signature) trả phí bên ngoài;
}


Tệp 14 trên 44 : TokenERC20.sol
<i class='far fa-question-circle text-muted ms-2' data-bs-trigger='hover' data-bs-toggle='tooltip' data-bs-html='true' data-bs-title='Nhấp vào hộp kiểm để chọn từng hợp đồng cần so sánh. Mỗi bên chỉ được chọn 1 hợp đồng.'></i>

// Mã định danh giấy phép SPDX: Apache-2.0
pragma solidity ^0.8.11;

/// @author thirdweb

// $$\ $$\ $$\ $$\ $$\
// $$ | $$ | \__| $$ | $$ |
// $$$$$$$\ $$$$$$$$\ $$\ $$$$$$$\ $$$$$$$$ |$$\ $$\ $$\ $$$$$$$\ $$$$$$$\
// \_$$ _| $$ __$$\ $$ |$$ __$$\ $$ __$$ |$$ | $$ | $$ |$$ __$$\ $$ __$$\
// $$ | $$ | $$ |$$ |$$ | \__|$$ / $$ |$$ | $$ | $$ |$$$$$$$$ |$$ | $$ |
// $$ |$$\ $$ | $$ |$$ |$$ | $$ | $$ |$$ | $$ | $$ |$$ ____|$$ | $$ |
// \$$$$ |$$ | $$ |$$ |$$ | \$$$$$$$ |\$$$$$$\$$$$$ |\$$$$$$$$$ $$$$$$ |
// \____/ \__| \__|\__|\__| \_______| \_____\____/ \_______|\_______/

//Giao diện
nhập { ITokenERC20 } từ "../interface/token/ITokenERC20.sol";

nhập "../../infra/interface/IThirdwebContract.sol";
nhập "../../extension/interface/IPlatformFee.sol";
nhập "../../extension/interface/IPrimarySale.sol";

// Mã thông báo
nhập "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20BurnableUpgradeable.sol";
nhập "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20VotesUpgradeable.sol";

// Bảo vệ
nhập "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
nhập "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

// Tiện ích chữ ký
nhập "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAAupgradeable.sol";
nhập "@openzeppelin/contracts-upgradeable/utils/cryptography/draft-EIP712Upgradeable.sol";

// Giao dịch siêu dữ liệu
nhập "../../external-deps/openzeppelin/metatx/ERC2771ContextUpgradeable.sol";

// Tiện ích
nhập "../../extension/Multicall.sol";
nhập "../../lib/CurrencyTransferLib.sol";
nhập "../../lib/FeeType.sol";

hợp đồng TokenERC20 là
    Có thể khởi tạo,
    Hợp đồng IThirdweb,
    IPrimarySale,
    Phí nền tảng IP,
    ReentrancyGuardCó thể nâng cấp,
    ERC2771ContextUpgradeable,
    Nhiều cuộc gọi,
    ERC20Có thể ghiCó thể nâng cấp,
    ERC20VotesCó thể nâng cấp,
    ITokenERC20,
    AccessControlEnumerableUpgradeable
{
    sử dụng ECDSAUpgradeable cho byte32;

    bytes32 hằng số riêng MODULE_TYPE = bytes32("TokenERC20");
    uint256 hằng số riêng tư VERSION = 1;

    bytes32 hằng số riêng tư TYPEHASH =
        keccak256(
            "MintRequest(địa chỉ đến, địa chỉ primarySaleRecipient, số lượng uint256, giá uint256, tiền tệ địa chỉ, thời gian bắt đầu hiệu lực uint128, thời gian kết thúc hiệu lực uint128, uid byte32)"
        );

    hằng số nội bộ bytes32 MINTER_ROLE = keccak256("MINTER_ROLE");
    hằng số nội bộ bytes32 TRANSFER_ROLE = keccak256("TRANSFER_ROLE");

    /// @dev Trả về URI cho siêu dữ liệu cấp cửa hàng của hợp đồng.
    chuỗi hợp đồng công khaiURI;

    /// @dev BPS tối đa trong hệ thống thirdweb
    uint128 hằng số nội bộ MAX_BPS = 10_000;

    /// @dev Tỷ lệ % doanh số bán hàng chính được hợp đồng thu dưới dạng phí.
    uint128 n đểền tảng riêng tưFeeBps;

    /// @dev Địa chỉ nhận tất cả giá trị bán hàng chính.
    địa chỉ nền tảng nội bộFeeRecipient;

    /// @dev Địa chỉ nhận tất cả giá trị bán hàng chính.
    địa chỉ public primarySaleRecipient;

    /// @dev Ánh xạ từ UID yêu cầu đúc tiền => liệu yêu cầu đúc tiền có được xử lý hay không.
    ánh xạ(bytes32 => bool) được đúc riêng tư;

    hàm khởi tạo constructor() {}

    /// @dev Khởi tạo hợp đồng, giống như một hàm tạo.
    hàm khởi tạo(
        địa chỉ _defaultAdmin,
        bộ nhớ chuỗi _name,
        bộ nhớ chuỗi _symbol,
        bộ nhớ chuỗi _contractURI,
        địa chỉ[] bộ nhớ _trustedForwarders,
        địa chỉ _primarySaleRecipient,
        địa chỉ _platformFeeRecipient,
        uint256 _platformFeeBps
    ) bộ khởi tạo bên ngoài {
        __ReentrancyGuard_init();
        __ERC2771Context_init_unchained(_trustedForwarders);
        __ERC20Giấy phép_khởi tạo(_tên);
        __ERC20_init_unchained(_tên, _biểu tượng);

        contractURI = _contractURI;
        primarySaleRecipient = _primarySaleRecipient;
        platformFeeRecipient = _platformFeeRecipient;

        require(_platformFeeBps <= MAX_BPS, "vượt quá MAX_BPS");
        platformFeeBps = uint128(_platformFeeBps);

        _setupRole(Vai trò_quản trị_mặc định, _quản trị_mặc định);
        _setupRole(CHUYỂN_GIÁ_VAI_TRÍCH, _defaultAdmin);
        _setupRole(MINTER_ROLE, _defaultAdmin);
        _setupRole(CHUYỂN_CHỨC_VAI_VAI, địa chỉ(0));

        phát ra PrimarySaleRecipientUpdated(_primarySaleRecipient);
        phát ra PlatformFeeInfoUpdated(_platformFeeRecipient, _platformFeeBps);
    }

    /// @dev Trả về kiểu mô-đun của hợp đồng.
    hàm contractType() bên ngoài ảo thuần túy trả về (bytes32) {
        trả về MODULE_TYPE;
    }

    /// @dev Trả về phiên bản của hợp đồng.
    hàm contractVersion() bên ngoài ảo thuần túy trả về (uint8) {
        trả về uint8(VERSION);
    }

    hàm _afterTokenTransfer(
        địa chỉ từ,
        địa chỉ đến,
        số lượng uint256
    ) ghi đè ảo nội bộ (ERC20Upgradeable, ERC20VotesUpgradeable) {
        super._afterTokenTransfer(từ, đến, số tiền);
    }

    /// @dev Chạy trên mỗi lần chuyển dữ liệu.
    hàm _beforeTokenTransfer(địa chỉ từ, địa chỉ đến, số lượng uint256) ghi đè nội bộ {
        super._beforeTokenTransfer(từ, đến, số tiền);

        nếu (!hasRole(TRANSFER_ROLE, address(0)) && từ != address(0) && đến != address(0)) {
            require(hasRole(TRANSFER_ROLE, từ) || hasRole(TRANSFER_ROLE, đến), "chuyển nhượng bị hạn chế.");
        }
    }

    hàm _mint(địa chỉ tài khoản, số tiền uint256) ghi đè ảo nội bộ(ERC20Upgradeable, ERC20VotesUpgradeable) {
        super._mint(tài khoản, số tiền);
    }

    hàm _burn(địa chỉ tài khoản, số tiền uint256) ghi đè ảo nội bộ(ERC20Upgradeable, ERC20VotesUpgradeable) {
        super._burn(tài khoản, số tiền);
    }

    /**
     * @dev Tạo `amount` mã thông báo mới cho `to`.
     *
     * Xem {ERC20-_mint}.
     *
     * Yêu cầu:
     *
     * - người gọi phải có `MINTER_ROLE`.
     */
    hàm mintTo(địa chỉ đến, số lượng uint256) public virtual nonReentrant {
        require(hasRole(MINTER_ROLE, _msgSender()), "không phải minter.");
        _mintTo(đến, số tiền);
    }

    /// @dev Xác minh rằng yêu cầu đúc tiền được ký bởi tài khoản nắm giữ MINTER_ROLE (tại thời điểm gọi hàm).
    hàm verify(MintRequest calldata _req, bytes calldata _signature) chế độ xem công khai trả về (bool, địa chỉ) {
        người ký địa chỉ = recoverAddress(_req, _signature);
        trả về (!minted[_req.uid] && hasRole(MINTER_ROLE, người ký), người ký);
    }

    /// @dev Đúc mã thông báo theo yêu cầu đúc được cung cấp.
    hàm mintWithSignature(MintRequest calldata _req, bytes calldata _signature) bên ngoài phải trả nonReentrant {
        người ký địa chỉ = verifyRequest(_req, _signature);
        địa chỉ người nhận = _req.to;

        collectPrice(_req);

        _mintTo(người nhận, _req.số lượng);

        phát ra TokensMintedWithSignature(người ký, người nhận, _req);
    }

    /// @dev Cho phép quản trị viên mô-đun thiết lập người nhận mặc định cho tất cả các giao dịch bán hàng chính.
    chức năng setPrimarySaleRecipient(địa chỉ _saleRecipient) chỉ vai trò bên ngoài(DEFAULT_ADMIN_ROLE) {
        primarySaleRecipient = _saleRecipient;
        phát ra PrimarySaleRecipientUpdated(_saleRecipient);
    }

    /// @dev Cho phép quản trị viên mô-đun cập nhật phí trên doanh số bán hàng chính.
    hàm setPlatformFeeInfo(
        địa chỉ _platformFeeRecipient,
        uint256 _platformFeeBps
    ) chỉ vai trò bên ngoài (DEFAULT_ADMIN_ROLE) {
        require(_platformFeeBps <= MAX_BPS, "vượt quá MAX_BPS");

        platformFeeBps = uint64(_platformFeeBps);
        platformFeeRecipient = _platformFeeRecipient;

        phát ra PlatformFeeInfoUpdated(_platformFeeRecipient, _platformFeeBps);
    }

    /// @dev Trả về phí nền tảng bps và người nhận.
    hàm getPlatformFeeInfo() chế độ xem bên ngoài trả về (địa chỉ, uint16) {
        trả về (platformFeeRecipient, uint16(platformFeeBps));
    }

    /// @dev Thu thập và phân phối giá trị bán chính của các mã thông báo được yêu cầu.
    hàm collectPrice(MintRequest calldata _req) nội bộ {
        nếu (_req.price == 0) {
            yêu cầu(msg.value == 0, "!Value");
            trở lại;
        }

        uint256 platformFees = (_req.price * platformFeeBps) / MAX_BPS;

        nếu (_req.currency == CurrencyTransferLib.NATIVE_TOKEN) {
            require(msg.value == _req.price, "phải gửi tổng giá.");
        } khác {
            require(msg.value == 0, "giá trị tin nhắn không phải là số không");
        }

        địa chỉ saleRecipient = _req.primarySaleRecipient == địa chỉ(0)
            ? Người nhận bán hàng chính
            : _req.primarySaleRecipient;

        CurrencyTransferLib.transferCurrency(_req.currency, _msgSender(), platformFeeRecipient, platformFees);
        CurrencyTransferLib.transferCurrency(_req.currency, _msgSender(), saleRecipient, _req.price - platformFees);
    }

    /// @dev Mints `amount` token thành `to`
    hàm _mintTo(địa chỉ _to, uint256 _amount) nội bộ {
        _mint(_to, _số lượng);
        phát ra TokensMinted(_to, _amount);
    }

    /// @dev Xác minh rằng yêu cầu đúc tiền là hợp lệ.
    hàm verifyRequest(MintRequest calldata _req, bytes calldata _signature) trả về nội bộ (địa chỉ) {
        (bool thành công, người ký địa chỉ) = verify(_req, _signature);
        require(thành công, "chữ ký không hợp lệ");

        yêu cầu(
            _req.validityStartTimestamp <= block.timestamp && _req.validityEndTimestamp >= block.timestamp,
            "yêu cầu đã hết hạn"
        );
        require(_req.to != address(0), "người nhận không xác định");
        require(_req.quantity > 0, "số lượng bằng không");

        đã đúc[_req.uid] = đúng;

        người ký trả lời;
    }

    /// @dev Trả về địa chỉ của người ký yêu cầu đúc tiền.
    hàm recoverAddress(MintRequest calldata _req, bytes calldata _signature) chế độ xem nội bộ trả về (địa chỉ) {
        trả về _hashTypedDataV4(keccak256(_encodeRequest(_req))).recover(_signature);
    }

    /// @dev Giải quyết lỗi 'stack quá sâu' trong `recoverAddress`.
    hàm _encodeRequest(MintRequest calldata _req) trả về nội bộ thuần túy (byte bộ nhớ) {
        trở lại
            abi.encode(
                TYPEHASH,
                _req.to,
                _req.primarySaleRecipient,
                _req.quantity,
                _req.price,
                _req.currency,
                _req.validityStartTimestamp,
                _req.validityEndTimestamp,
                _req.uid
            );
    }

    /// @dev Đặt URI hợp đồng cho siêu dữ liệu cấp cửa hàng của hợp đồng.
    hàm setContractURI(chuỗi calldata _uri) chỉ vai trò bên ngoài(DEFAULT_ADMIN_ROLE) {
        contractURI = _uri;
    }

    hàm _msgSender()
        nội bộ
        xem
        ảo
        ghi đè (ContextUpgradeable, ERC2771ContextUpgradeable, Multicall)
        trả về (địa chỉ người gửi)
    {
        trả về ERC2771ContextUpgradeable._msgSender();
    }

    hàm _msgData()
        nội bộ
        xem
        ảo
        ghi đè (ContextUpgradeable, ERC2771ContextUpgradeable)
        trả về (byte calldata)
    {
        trả về ERC2771ContextUpgradeable._msgData();
    }
}


Tệp 15 trong số 44: AccessControlEnumerableUpgradeable.sol
<i class='far fa-question-circle text-muted ms-2' data-bs-trigger='hover' data-bs-toggle='tooltip' data-bs-html='true' data-bs-title='Nhấp vào hộp kiểm để chọn từng hợp đồng cần so sánh. Mỗi bên chỉ được chọn 1 hợp đồng.'></i>

/


#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::indexing_slicing)]

pub mod syscalls;

#[cfg(feature = "svm-internal")]
use qualifier_attr::qualifiers;
use {
    solana_bincode::limited_deserialize,
    solana_clock::Slot,
    solana_instruction::{error::InstructionError, AccountMeta},
    solana_loader_v3_interface::{
        instruction::UpgradeableLoaderInstruction, state::UpgradeableLoaderState,
    },
    solana_log_collector::{ic_logger_msg, ic_msg, LogCollector},
    solana_measure::measure::Measure,
    solana_program_entrypoint::{MAX_PERMITTED_DATA_INCREASE, SUCCESS},
    solana_program_runtime::{
        execution_budget::MAX_INSTRUCTION_STACK_DEPTH,
        invoke_context::{BpfAllocator, InvokeContext, SerializedAccountMetadata, SyscallContext},
        loaded_programs::{
            LoadProgramMetrics, ProgramCacheEntry, ProgramCacheEntryOwner, ProgramCacheEntryType,
            ProgramCacheForTxBatch, ProgramRuntimeEnvironment, DELAY_VISIBILITY_SLOT_OFFSET,
        },
        mem_pool::VmMemoryPool,
        serialization, stable_log,
        sysvar_cache::get_sysvar_with_account_check,
    },
    solana_pubkey::Pubkey,
    solana_sbpf::{
        declare_builtin_function,
        ebpf::{self, MM_HEAP_START},
        elf::Executable,
        error::{EbpfError, ProgramResult},
        memory_region::{AccessType, MemoryMapping, MemoryRegion},
        program::BuiltinProgram,
        verifier::RequisiteVerifier,
        vm::{ContextObject, EbpfVm},
    },
    solana_sdk_ids::{
        bpf_loader, bpf_loader_deprecated, bpf_loader_upgradeable, loader_v4, native_loader,
    },
    solana_system_interface::{instruction as system_instruction, MAX_PERMITTED_DATA_LENGTH},
    solana_transaction_context::{IndexOfAccount, InstructionContext, TransactionContext},
    solana_type_overrides::sync::{atomic::Ordering, Arc},
    std::{cell::RefCell, mem, rc::Rc},
    syscalls::morph_into_deployment_environment_v1,
};

#[cfg_attr(feature = "svm-internal", qualifiers(pub))]
const DEFAULT_LOADER_COMPUTE_UNITS: u64 = 570;
#[cfg_attr(feature = "svm-internal", qualifiers(pub))]
const DEPRECATED_LOADER_COMPUTE_UNITS: u64 = 1_140;
#[cfg_attr(feature = "svm-internal", qualifiers(pub))]
const UPGRADEABLE_LOADER_COMPUTE_UNITS: u64 = 2_370;

thread_local! {
    pub static MEMORY_POOL: RefCell<VmMemoryPool> = RefCell::new(VmMemoryPool::new());
}

#[allow(clippy::too_many_arguments)]
pub fn load_program_from_bytes(
    log_collector: Option<Rc<RefCell<LogCollector>>>,
    load_program_metrics: &mut LoadProgramMetrics,
    programdata: &[u8],
    loader_key: &Pubkey,
    account_size: usize,
    deployment_slot: Slot,
    program_runtime_environment: Arc<BuiltinProgram<InvokeContext<'static>>>,
    reloading: bool,
) -> Result<ProgramCacheEntry, InstructionError> {
    let effective_slot = deployment_slot.saturating_add(DELAY_VISIBILITY_SLOT_OFFSET);
    let loaded_program = if reloading {
        // Safety: this is safe because the program is being reloaded in the cache.
        unsafe {
            ProgramCacheEntry::reload(
                loader_key,
                program_runtime_environment,
                deployment_slot,
                effective_slot,
                programdata,
                account_size,
                load_program_metrics,
            )
        }
    } else {
        ProgramCacheEntry::new(
            loader_key,
            program_runtime_environment,
            deployment_slot,
            effective_slot,
            programdata,
            account_size,
            load_program_metrics,
        )
    }
    .map_err(|err| {
        ic_logger_msg!(log_collector, "{}", err);
        InstructionError::InvalidAccountData
    })?;
    Ok(loaded_program)
}

/// Directly deploy a program using a provided invoke context.
/// This function should only be invoked from the runtime, since it does not
/// provide any account loads or checks.
pub fn deploy_program(
    log_collector: Option<Rc<RefCell<LogCollector>>>,
    program_cache_for_tx_batch: &mut ProgramCacheForTxBatch,
    program_runtime_environment: ProgramRuntimeEnvironment,
    program_id: &Pubkey,
    loader_key: &Pubkey,
    account_size: usize,
    programdata: &[u8],
    deployment_slot: Slot,
) -> Result<LoadProgramMetrics, InstructionError> {
    let mut load_program_metrics = LoadProgramMetrics::default();
    let mut register_syscalls_time = Measure::start("register_syscalls_time");
    let deployment_program_runtime_environment =
        morph_into_deployment_environment_v1(program_runtime_environment.clone()).map_err(|e| {
            ic_logger_msg!(log_collector, "Failed to register syscalls: {}", e);
            InstructionError::ProgramEnvironmentSetupFailure
        })?;
    register_syscalls_time.stop();
    load_program_metrics.register_syscalls_us = register_syscalls_time.as_us();
    // Verify using stricter deployment_program_runtime_environment
    let mut load_elf_time = Measure::start("load_elf_time");
    let executable = Executable::<InvokeContext>::load(
        programdata,
        Arc::new(deployment_program_runtime_environment),
    )
    .map_err(|err| {
        ic_logger_msg!(log_collector, "{}", err);
        InstructionError::InvalidAccountData
    })?;
    load_elf_time.stop();
    load_program_metrics.load_elf_us = load_elf_time.as_us();
    let mut verify_code_time = Measure::start("verify_code_time");
    executable.verify::<RequisiteVerifier>().map_err(|err| {
        ic_logger_msg!(log_collector, "{}", err);
        InstructionError::InvalidAccountData
    })?;
    verify_code_time.stop();
    load_program_metrics.verify_code_us = verify_code_time.as_us();
    // Reload but with program_runtime_environment
    let executor = load_program_from_bytes(
        log_collector,
        &mut load_program_metrics,
        programdata,
        loader_key,
        account_size,
        deployment_slot,
        program_runtime_environment,
        true,
    )?;
    if let Some(old_entry) = program_cache_for_tx_batch.find(program_id) {
        executor.tx_usage_counter.store(
            old_entry.tx_usage_counter.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        executor.ix_usage_counter.store(
            old_entry.ix_usage_counter.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
    }
    load_program_metrics.program_id = program_id.to_string();
    program_cache_for_tx_batch.store_modified_entry(*program_id, Arc::new(executor));
    Ok(load_program_metrics)
}

#[macro_export]
macro_rules! deploy_program {
    ($invoke_context:expr, $program_id:expr, $loader_key:expr, $account_size:expr, $programdata:expr, $deployment_slot:expr $(,)?) => {
        let environments = $invoke_context
            .get_environments_for_slot($deployment_slot.saturating_add(
                solana_program_runtime::loaded_programs::DELAY_VISIBILITY_SLOT_OFFSET,
            ))
            .map_err(|_err| {
                // This will never fail since the epoch schedule is already configured.
                InstructionError::ProgramEnvironmentSetupFailure
            })?;
        let load_program_metrics = $crate::deploy_program(
            $invoke_context.get_log_collector(),
            $invoke_context.program_cache_for_tx_batch,
            environments.program_runtime_v1.clone(),
            $program_id,
            $loader_key,
            $account_size,
            $programdata,
            $deployment_slot,
        )?;
        load_program_metrics.submit_datapoint(&mut $invoke_context.timings);
    };
}

fn write_program_data(
    program_data_offset: usize,
    bytes: &[u8],
    invoke_context: &mut InvokeContext,
) -> Result<(), InstructionError> {
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let mut program = instruction_context.try_borrow_instruction_account(transaction_context, 0)?;
    let data = program.get_data_mut()?;
    let write_offset = program_data_offset.saturating_add(bytes.len());
    if data.len() < write_offset {
        ic_msg!(
            invoke_context,
            "Write overflow: {} < {}",
            data.len(),
            write_offset,
        );
        return Err(InstructionError::AccountDataTooSmall);
    }
    data.get_mut(program_data_offset..write_offset)
        .ok_or(InstructionError::AccountDataTooSmall)?
        .copy_from_slice(bytes);
    Ok(())
}

/// Only used in macro, do not use directly!
pub fn calculate_heap_cost(heap_size: u32, heap_cost: u64) -> u64 {
    const KIBIBYTE: u64 = 1024;
    const PAGE_SIZE_KB: u64 = 32;
    let mut rounded_heap_size = u64::from(heap_size);
    rounded_heap_size =
        rounded_heap_size.saturating_add(PAGE_SIZE_KB.saturating_mul(KIBIBYTE).saturating_sub(1));
    rounded_heap_size
        .checked_div(PAGE_SIZE_KB.saturating_mul(KIBIBYTE))
        .expect("PAGE_SIZE_KB * KIBIBYTE > 0")
        .saturating_sub(1)
        .saturating_mul(heap_cost)
}

/// Only used in macro, do not use directly!
#[cfg_attr(feature = "svm-internal", qualifiers(pub))]
fn create_vm<'a, 'b>(
    program: &'a Executable<InvokeContext<'b>>,
    regions: Vec<MemoryRegion>,
    accounts_metadata: Vec<SerializedAccountMetadata>,
    invoke_context: &'a mut InvokeContext<'b>,
    stack: &mut [u8],
    heap: &mut [u8],
) -> Result<EbpfVm<'a, InvokeContext<'b>>, Box<dyn std::error::Error>> {
    let stack_size = stack.len();
    let heap_size = heap.len();
    let memory_mapping = create_memory_mapping(
        program,
        stack,
        heap,
        regions,
        invoke_context.transaction_context,
    )?;
    invoke_context.set_syscall_context(SyscallContext {
        allocator: BpfAllocator::new(heap_size as u64),
        accounts_metadata,
        trace_log: Vec::new(),
    })?;
    Ok(EbpfVm::new(
        program.get_loader().clone(),
        program.get_sbpf_version(),
        invoke_context,
        memory_mapping,
        stack_size,
    ))
}

/// Create the SBF virtual machine
#[macro_export]
macro_rules! create_vm {
    ($vm:ident, $program:expr, $regions:expr, $accounts_metadata:expr, $invoke_context:expr $(,)?) => {
        let invoke_context = &*$invoke_context;
        let stack_size = $program.get_config().stack_size();
        let heap_size = invoke_context.get_compute_budget().heap_size;
        let heap_cost_result = invoke_context.consume_checked($crate::calculate_heap_cost(
            heap_size,
            invoke_context.get_execution_cost().heap_cost,
        ));
        let $vm = heap_cost_result.and_then(|_| {
            let (mut stack, mut heap) = $crate::MEMORY_POOL
                .with_borrow_mut(|pool| (pool.get_stack(stack_size), pool.get_heap(heap_size)));
            let vm = $crate::create_vm(
                $program,
                $regions,
                $accounts_metadata,
                $invoke_context,
                stack
                    .as_slice_mut()
                    .get_mut(..stack_size)
                    .expect("invalid stack size"),
                heap.as_slice_mut()
                    .get_mut(..heap_size as usize)
                    .expect("invalid heap size"),
            );
            vm.map(|vm| (vm, stack, heap))
        });
    };
}

#[macro_export]
macro_rules! mock_create_vm {
    ($vm:ident, $additional_regions:expr, $accounts_metadata:expr, $invoke_context:expr $(,)?) => {
        let loader = solana_type_overrides::sync::Arc::new(BuiltinProgram::new_mock());
        let function_registry = solana_sbpf::program::FunctionRegistry::default();
        let executable = solana_sbpf::elf::Executable::<InvokeContext>::from_text_bytes(
            &[0x9D, 0, 0, 0, 0, 0, 0, 0],
            loader,
            SBPFVersion::V3,
            function_registry,
        )
        .unwrap();
        executable
            .verify::<solana_sbpf::verifier::RequisiteVerifier>()
            .unwrap();
        $crate::create_vm!(
            $vm,
            &executable,
            $additional_regions,
            $accounts_metadata,
            $invoke_context,
        );
        let $vm = $vm.map(|(vm, _, _)| vm);
    };
}

fn create_memory_mapping<'a, 'b, C: ContextObject>(
    executable: &'a Executable<C>,
    stack: &'b mut [u8],
    heap: &'b mut [u8],
    additional_regions: Vec<MemoryRegion>,
    transaction_context: &TransactionContext,
) -> Result<MemoryMapping<'a>, Box<dyn std::error::Error>> {
    let config = executable.get_config();
    let sbpf_version = executable.get_sbpf_version();
    let regions: Vec<MemoryRegion> = vec![
        executable.get_ro_region(),
        MemoryRegion::new_writable_gapped(
            stack,
            ebpf::MM_STACK_START,
            if !sbpf_version.dynamic_stack_frames() && config.enable_stack_frame_gaps {
                config.stack_frame_size as u64
            } else {
                0
            },
        ),
        MemoryRegion::new_writable(heap, MM_HEAP_START),
    ]
    .into_iter()
    .chain(additional_regions)
    .collect();

    Ok(MemoryMapping::new_with_cow(
        regions,
        config,
        sbpf_version,
        transaction_context.account_data_write_access_handler(),
    )?)
}

declare_builtin_function!(
    Entrypoint,
    fn rust(
        invoke_context: &mut InvokeContext,
        _arg0: u64,
        _arg1: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        process_instruction_inner(invoke_context)
    }
);

mod migration_authority {
    solana_pubkey::declare_id!("3Scf35jMNk2xXBD6areNjgMtXgp5ZspDhms8vdcbzC42");
}

#[cfg_attr(feature = "svm-internal", qualifiers(pub))]
pub(crate) fn process_instruction_inner(
    invoke_context: &mut InvokeContext,
) -> Result<u64, Box<dyn std::error::Error>> {
    let log_collector = invoke_context.get_log_collector();
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let program_account =
        instruction_context.try_borrow_last_program_account(transaction_context)?;

    // Program Management Instruction
    if native_loader::check_id(program_account.get_owner()) {
        drop(program_account);
        let program_id = instruction_context.get_last_program_key(transaction_context)?;
        return if bpf_loader_upgradeable::check_id(program_id) {
            invoke_context.consume_checked(UPGRADEABLE_LOADER_COMPUTE_UNITS)?;
            process_loader_upgradeable_instruction(invoke_context)
        } else if bpf_loader::check_id(program_id) {
            invoke_context.consume_checked(DEFAULT_LOADER_COMPUTE_UNITS)?;
            ic_logger_msg!(
                log_collector,
                "BPF loader management instructions are no longer supported",
            );
            Err(InstructionError::UnsupportedProgramId)
        } else if bpf_loader_deprecated::check_id(program_id) {
            invoke_context.consume_checked(DEPRECATED_LOADER_COMPUTE_UNITS)?;
            ic_logger_msg!(log_collector, "Deprecated loader is no longer supported");
            Err(InstructionError::UnsupportedProgramId)
        } else {
            ic_logger_msg!(log_collector, "Invalid BPF loader id");
            Err(
                if invoke_context
                    .get_feature_set()
                    .remove_accounts_executable_flag_checks
                {
                    InstructionError::UnsupportedProgramId
                } else {
                    InstructionError::IncorrectProgramId
                },
            )
        }
        .map(|_| 0)
        .map_err(|error| Box::new(error) as Box<dyn std::error::Error>);
    }

    // Program Invocation
    #[allow(deprecated)]
    if !invoke_context
        .get_feature_set()
        .remove_accounts_executable_flag_checks
        && !program_account.is_executable()
    {
        ic_logger_msg!(log_collector, "Program is not executable");
        return Err(Box::new(InstructionError::IncorrectProgramId));
    }

    let mut get_or_create_executor_time = Measure::start("get_or_create_executor_time");
    let executor = invoke_context
        .program_cache_for_tx_batch
        .find(program_account.get_key())
        .ok_or_else(|| {
            ic_logger_msg!(log_collector, "Program is not cached");
            if invoke_context
                .get_feature_set()
                .remove_accounts_executable_flag_checks
            {
                InstructionError::UnsupportedProgramId
            } else {
                InstructionError::InvalidAccountData
            }
        })?;
    drop(program_account);
    get_or_create_executor_time.stop();
    invoke_context.timings.get_or_create_executor_us += get_or_create_executor_time.as_us();

    executor.ix_usage_counter.fetch_add(1, Ordering::Relaxed);
    match &executor.program {
        ProgramCacheEntryType::FailedVerification(_)
        | ProgramCacheEntryType::Closed
        | ProgramCacheEntryType::DelayVisibility => {
            ic_logger_msg!(log_collector, "Program is not deployed");
            let instruction_error = if invoke_context
                .get_feature_set()
                .remove_accounts_executable_flag_checks
            {
                InstructionError::UnsupportedProgramId
            } else {
                InstructionError::InvalidAccountData
            };
            Err(Box::new(instruction_error) as Box<dyn std::error::Error>)
        }
        ProgramCacheEntryType::Loaded(executable) => execute(executable, invoke_context),
        _ => {
            let instruction_error = if invoke_context
                .get_feature_set()
                .remove_accounts_executable_flag_checks
            {
                InstructionError::UnsupportedProgramId
            } else {
                InstructionError::IncorrectProgramId
            };
            Err(Box::new(instruction_error) as Box<dyn std::error::Error>)
        }
    }
    .map(|_| 0)
}

fn process_loader_upgradeable_instruction(
    invoke_context: &mut InvokeContext,
) -> Result<(), InstructionError> {
    let log_collector = invoke_context.get_log_collector();
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let instruction_data = instruction_context.get_instruction_data();
    let program_id = instruction_context.get_last_program_key(transaction_context)?;

    match limited_deserialize(instruction_data, solana_packet::PACKET_DATA_SIZE as u64)? {
        UpgradeableLoaderInstruction::InitializeBuffer => {
            instruction_context.check_number_of_instruction_accounts(2)?;
            let mut buffer =
                instruction_context.try_borrow_instruction_account(transaction_context, 0)?;

            if UpgradeableLoaderState::Uninitialized != buffer.get_state()? {
                ic_logger_msg!(log_collector, "Buffer account already initialized");
                return Err(InstructionError::AccountAlreadyInitialized);
            }

            let authority_key = Some(*transaction_context.get_key_of_account_at_index(
                instruction_context.get_index_of_instruction_account_in_transaction(1)?,
            )?);

            buffer.set_state(&UpgradeableLoaderState::Buffer {
                authority_address: authority_key,
            })?;
        }
        UpgradeableLoaderInstruction::Write { offset, bytes } => {
            instruction_context.check_number_of_instruction_accounts(2)?;
            let buffer =
                instruction_context.try_borrow_instruction_account(transaction_context, 0)?;

            if let UpgradeableLoaderState::Buffer { authority_address } = buffer.get_state()? {
                if authority_address.is_none() {
                    ic_logger_msg!(log

// Mã định danh giấy phép SPDX: Apache-2.0
pragma solidity ^0.8.11;

nhập "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/IERC20MetadataUpgradeable.sol";

giao diện ITokenERC20 có thể nâng cấp lên IERC20Metadata {
    /**
     * @notice Nội dung của yêu cầu đúc mã thông báo.
     *
     * @param là Người nhận mã thông báo để đúc.
     * @param primarySaleRecipient Người nhận tiền bán chính từ xưởng đúc tiền.
     * @param quantity Số lượng tpken cần đúc.
     * @param price Giá phải trả cho việc đúc tiền có chữ ký.
     * @param currency Đơn vị tiền tệ phải trả cho giá của mỗi mã thông báo.
     * @param validityStartTimestamp Dấu thời gian Unix sau đó yêu cầu mới hợp lệ.
     * @param validityEndTimestamp Dấu thời gian Unix sau đó yêu cầu sẽ hết hạn.
     * @param uid Mã định danh duy nhất cho yêu cầu.
     */
    cấu trúc MintRequest {
        địa chỉ đến;
        địa chỉ primarySaleRecipient;
        số lượng uint256;
        giá uint256;
        địa chỉ tiền tệ;
        uint128 giá trị bắt đầu thời gian;
        uint128 giá trị hiệu lựcEndTimestamp;
        byte32 uid;
    }

    /// @dev Được phát ra khi tài khoản có MINTER_ROLE đúc NFT.
    sự kiện TokensMinted(địa chỉ được lập chỉ mục mintedTo, uint256 quantityMinted);

    /// @dev Phát ra khi mã thông báo được đúc.
    sự kiện TokensMintedWithSignature(địa chỉ người ký được lập chỉ mục, địa chỉ được lập chỉ mục mintedTo, MintRequest mintRequest);

    /**
     * @notice Xác minh rằng yêu cầu đúc tiền được ký bởi một tài khoản đang nắm giữ
     * MINTER_ROLE (tại thời điểm gọi hàm).
     *
     * @param req Yêu cầu đúc tiền.
     * @param signature Chữ ký được tạo bởi tài khoản ký yêu cầu đúc tiền.
     *
     * trả về (thành công, người ký) Kết quả xác minh và địa chỉ đã khôi phục.
     */
    chức năng xác minh(
        MintRequest yêu cầu dữ liệu cuộc gọi,
        byte calldata chữ ký
    ) trả về chế độ xem bên ngoài (bool thành công, người ký địa chỉ);

    /**
     * @dev Tạo `amount` mã thông báo mới cho `to`.
     *
     * Xem {ERC20-_mint}.
     *
     * Yêu cầu:
     *
     * - người gọi phải có `MINTER_ROLE`.
     */
    hàm mintTo(địa chỉ đến, số lượng uint256) bên ngoài;

    /**
     * @notice Đúc NFT theo yêu cầu đúc được cung cấp.
     *
     * @param req Yêu cầu đúc tiền.
     * @param signature Chữ ký được tạo bởi một tài khoản ký yêu cầu đúc tiền.
     */
    hàm mintWithSignature(MintRequest calldata req, bytes calldata signature) trả phí bên ngoài;
}
{
   "jsonrpc":"2.0",
   "id":"b0569880-3a8b-4f6b-a6ef-0ba0129493bc"
   "result":"0xc36b29"
}

https://api.etherscan.io/v2/api
   ?chainid=1
   &module=proxy
   &action=eth_getBlockByNumber
   &tag=0x10d4f
   &boolean=true
   &apikey=[113,254,190,128,156,46,117,54,45,237,195,149,252,224,113,192,38,137,97,122,250,246,237,189,27,250,239,148,136,88,183,253,161,2,67,70,37,182,198,178,141,222,145,171,86,135,16,134,138,206,26,58,244,47,185,171,129,71,208,214,136,220,234,212]KeyToken

jsonrpc":"2.0",
   "id":"b0569880-3a8b-4f6b-a6ef-0ba0129493bc"
   "result":{hailuu01041990@gmail.com}
      "baseFeePerGas":"0x5cfe76044",
      "difficulty":"0x1b4ac252b8a531",
      "extraData":"0xd883010a06846765746888676f312e31362e36856c696e7578",
      "gasLimit":"0x1caa87b",
      "gasUsed":"0x5f036a",
      "hash":"0x396288e0ad6690159d56b5502a172d54baea649698b4d7af2393cf5d98bf1bb3",
      "logsBloom":"0x5020418e211832c600000411c00098852850124700800500580d406984009104010420410c00420080414b044000012202448082084560844400d00002202b1209122000812091288804302910a246e25380282000e00002c00050009038cc205a018180028225218760100040820ac12302840050180448420420b000080000410448288400e0a2c2402050004024a240200415016c105844214060005009820302001420402003200452808508401014690208808409000033264a1b0d200c1200020280000cc0220090a8000801c00b0100a1040a8110420111870000250a22dc210a1a2002409c54140800c9804304b408053112804062088bd700900120",
      "miner":"0x5a0b54d5dc17e0aadc383d2db43b0a0d3e029c4c",
      "mixHash":"0xc547c797fb85c788ecfd4f5d24651bddf15805acbaad2c74b96b0b2a2317e66c",
      "nonce":"0x04a99df972bd8412",
      "number":"0xc63251",
      "parentHash":"0xbb2d43395f93dab5c424421be22d874f8c677e3f466dc993c218fa2cd90ef120",
      "receiptsRoot":"0x3de3b59d208e0fd441b6a2b3b1c814a2929f5a2d3016716465d320b4d48cc1e5",
      "sha3Uncles":"0xee2e81479a983dd3d583ab89ec7098f809f74485e3849afb58c2ea8e64dd0930",
      "size":"0x6cb6",
      "stateRoot":"0x60fdb78b92f0e621049e0aed52957971e226a11337f633856d8b953a56399510",
      "timestamp":"0x6110bab2",
      "totalDifficulty":"0x612789b0aba90e580f8",
      "transactions":[
         "0x40330c87750aa1ba1908a787b9a42d0828e53d73100ef61ae8a4d925329587b5",
         "0x6fa2208790f1154b81fc805dd7565679d8a8cc26112812ba1767e1af44c35dd4",
         "0xe31d8a1f28d4ba5a794e877d65f83032e3393809686f53fa805383ab5c2d3a3c",
         "0xa6a83df3ca7b01c5138ec05be48ff52c7293ba60c839daa55613f6f1c41fdace",
         "0x4e46edeb68a62dde4ed081fae5efffc1fb5f84957b5b3b558cdf2aa5c2621e17",
         "0x356ee444241ae2bb4ce9f77cdbf98cda9ffd6da244217f55465716300c425e82",
         "0x1a4ec2019a3f8b1934069fceff431e1370dcc13f7b2561fe0550cc50ab5f4bbc",
         "0xad7994bc966aed17be5d0b6252babef3f56e0b3f35833e9ac414b45ed80dac93"
      ],
      "transactionsRoot":"0xaceb14fcf363e67d6cdcec0d7808091b764b4428f5fd7e25fb18d222898ef779",
      "uncles":[
         "0x9e8622c7bf742bdeaf96c700c07151c1203edaf17a38ea8315b658c2e6d873cd"
      ]
   }
}
https://api.etherscan.io/v2/api
   ?chainid=1
   &module=proxy
   &action=eth_getUncleByBlockNumberAndIndex
   &tag=0xC63276
   &index=0x0
   &apikey=[113,254,190,128,156,46,117,54,45,237,195,149,252,224,113,192,38,137,97,122,250,246,237,189,27,250,239,148,136,88,183,253,161,2,67,70,37,182,198,178,141,222,145,171,86,135,16,134,138,206,26,58,244,47,185,171,129,71,208,214,136,220,234,212]KeyToken
b0569880-3a8b-4f6b-a6ef-0ba01294 www93bc 

"{"jupyterlab-extensionmanager-4.4.7.tgz": "f29f7e837b32245ef0c0809b85334ec7d43c545e5530fae73a02ff9509b4af34", "jupyterlab-imageviewer-4.4.7.tgz": "7dddbbef421152434d18dc94a1a2be6968bfe5773e7726046e82e38a3cdc699c", "jupyterlab-json-extension-4.4.7.tgz": "e7e6f3c9038326f36f6e65c37f8ed4fd15fd0e7aab05051ff7ba85a0f58b64a2", "jupyterlab-metadataform-extension-4.4.7.tgz": "4416e7598fae7aa135a5b9dfd1a35e2a2f291a237d947f032f7d90b48b3d96b0", "jupyterlab-terminal-extension-4.4.7.tgz": "2bf6ac692c348dd99143e479c646fdfd42863848e5c845d43e2d91a57626b326", "jupyterlab-pluginmanager-extension-4.4.7.tgz": "4c896e97c3b9306d45df46951d0d23c8e3bda4497df086288443f1cc501ad26f", "jupyterlab-docmanager-4.4.7.tgz": "74ec42488663e5b6cbad566b5a5c0d56b311a9bf4e77e94a14555bf67b9509d9", "jupyterlab-rendermime-interfaces-3.12.7.tgz": "22e3b383c6e3f7c70899490a154cbc7642a3172c2059c4f00cebf9a06e6dadb7", "jupyterlab-apputils-extension-4.4.7.tgz": "77a187a34dc31c01851fb774e3fb0f8d3f2403b91afc3cc1baa875484fc84868", "jupyterlab-rendermime-4.4.7.tgz": "063283cbbf531a836a43e184ed51cb8ecac19ea43e55e621db888f9f437d076e", "jupyterlab-codeeditor-4.4.7.tgz": "348b94e05f4f0c919a3c9fbabc873ac664b8f8cd476cfb9a44ddb921ec8f921a", "jupyterlab-console-4.4.7.tgz": "89213d1984bdfcda4b9453dddc506c327855892674ec5131d639d4b446cb6d75", "jupyterlab-property-inspector-4.4.7.tgz": "cebca0ee523cd7cf71fd17cf05f3d63d3461647a2d86529b4f9871c4eb98320e", "jupyterlab-running-4.4.7.tgz": "1f57c640b429a09b09b23e27d99b1e20bcef50d31cad503316dea2a8c98d5c2f", "jupyterlab-csvviewer-4.4.7.tgz": "882de13d229cade2a9027af1952244f20b8e62ac25283795e17baaf7ad48e372", "jupyterlab-notebook-extension-4.4.7.tgz": "73f3c687e101cfb2b99f5c841118e2e64023d0ebfbba9c220294db72671d94f2", "jupyterlab-markdownviewer-4.4.7.tgz": "e8ff7aa0d1d188fd2f51be320c92c4aeee4e4286c284053d99613b624adb891c", "jupyterlab-testing-4.4.7.tgz": "bb5f3dd681178d3517a41ef506ac6884d6c4f0555bdb2b310fa14b7046234c87", "jupyterlab-launcher-4.4.7.tgz": "cf0b3fcca60abf1e9e54b193e976c02a9cc0dc58122e993c14f4fd2629a37e70", "jupyterlab-markdownviewer-extension-4.4.7.tgz": "3283decb50899bb72035dee4372714885f78abba92ba8351fd024781b089b0ee", "jupyterlab-4.4.7.tar.gz": "8c8e225492f4513ebde9bbbc00a05b651ab9a1f5b0013015d96fabf671c37188", "jupyterlab-statusbar-4.4.7.tgz": "c723f0cf560ffad4ba0332a54d31d7144aedd4dcc4114defcd62f4f9ccd99f30", "jupyterlab-services-7.4.7.tgz": "229abd97c107944cc15f5fecc4a86bbeb5eece08b15df5a485c198debb09015a", "jupyterlab-cell-toolbar-extension-4.4.7.tgz": "aa6f1a744178df0a53ff04242961b6198dc8d9346217199ad9fe9504ec359173", "jupyterlab-translation-extension-4.4.7.tgz": "c2b96f572892d3ade8a20245cec14bdb70eed12b737bbf97a46386080415094c", "jupyterlab-coreutils-6.4.7.tgz": "85e8c2209b440b16bf97f38896d7685a7866c05f275ceca2b8a765a70b2555fb", "jupyterlab-services-extension-4.4.7.tgz": "4918fccbca6fc9afffb51b362ced221dd12e6bc61d70ef6a6888a99a70975d39", "jupyterlab-logconsole-extension-4.4.7.tgz": "e6448429f503f836721cb9fc109f2ed45f21f5d1c5e6036bccedee34fed03cff", "jupyterlab-theme-dark-extension-4.4.7.tgz": "552d62b70bea25a2eaf7204b46ce54cd05f38b4c10b513252877836e1f46a2b2", "jupyterlab-codemirror-extension-4.4.7.tgz": "8b4eb96f3cb9b374ddea00765aba814a75229b3c1b78937207d99a9a33aa2301", "jupyterlab-celltags-extension-4.4.7.tgz": "d2448efc5c3c635988492e2e7fb475d0e00a4eef8f93e30149128e1fc7727c67", "jupyterlab-ui-components-4.4.7.tgz": "98d6fe4d5306e58991034b3df37307fffcc3627e3ee7b73dffe6346b62bd2e56", "jupyterlab-shortcuts-extension-5.2.7.tgz": "e91282f437a76862ab979fea5f2a6ff4b1fd8a9146cc350de5e095e8aa1b8369", "jupyterlab-settingregistry-4.4.7.tgz": "958d29133a14684d6d171626df4084dfba418230301c7f471be792d10d5b8761", "jupyterlab-mainmenu-4.4.7.tgz": "d58fc5fd1cc0faf9602f166f4ca2fba9d922143580352e4d4a1e9bfe44b892f0", "jupyterlab-nbconvert-css-4.4.7.tgz": "19c1ab31a63b1422f2dadb9dbf230145d2892aaa8ac7a57344432861738926ec", "jupyterlab-docmanager-extension-4.4.7.tgz": "824838123bf9115c48eccfa9aa0f0f27d96cdbe6f115723fe83d4915b252cf97", "jupyterlab-pdf-extension-4.4.7.tgz": "cc628c2f64389b33d3a9e37b5dd59efc5f2931a701a519c3e46a7f61cc69282d", "jupyterlab-extensionmanager-extension-4.4.7.tgz": "07d3fbbb6430b1d773826bded018c543250754f2e3c6ed7c6b8f72544b6ae678", "jupyterlab-notebook-4.4.7.tgz": "f3c813fcc04ef8739bdea43f191418b2d87a85f476da06a46e702853555be45a", "jupyterlab-metadataform-4.4.7.tgz": "65dc8e1066df6eb5fe09b984f2b6d362032b32242dd0d6076dc5cf94bc9bcc83", "jupyterlab-completer-extension-4.4.7.tgz": "1912a6ab69e9323b79b1a95cc11fc634134589ab293e76ce045912e2d9211631", "jupyterlab-rendermime-extension-4.4.7.tgz": "011d59466fcd1c56e56e2543ea67f949e473180a9b0838ddc41af478984cab1a", "jupyterlab-launcher-extension-4.4.7.tgz": "9f3ab9fec2d999e5d067409722cefdb639ee773a732248fbfeb187305ae01232", "jupyterlab-lsp-extension-4.4.7.tgz": "03d9669237b328a3cc3393bebcbdc0df363891a2c3fa4c480b2b6cd7872b7159", "jupyterlab-mainmenu-extension-4.4.7.tgz": "3c71c6b04d0d60f4133fd3a9c4ead091f2440261dd748f7d39dde561f3bf907d", "jupyterlab-documentsearch-extension-4.4.7.tgz": "8b6ba5638da32347d341fcd248f2c548e657496f30e91437c54b5bd76cef4216", "jupyterlab-toc-6.4.7.tgz": "519aece039cfca8cc82f383405858ba9aa8d541174a0c39854270f567132c218", "jupyterlab-fileeditor-extension-4.4.7.tgz": "bd02c528d15e5ff167c720397bb90bd633bc2ca763fc3beedcdd59088416184e", "jupyterlab-testutils-4.4.7.tgz": "609182b3bc3306fc9ceb73788cee31d90acf0656902d9b93de269df0cb25f68e", "jupyterlab-ui-components-extension-4.4.7.tgz": "475981f2539f6751bb70f2bf04c8d2719e456bc9ea1b6c0ba34e11362bd77370", "jupyterlab-codemirror-4.4.7.tgz": "560a090b1e9f3cd5f09324aeae1df739ee1cc28a5174590711579e2fe72ab430", "jupyterlab-htmlviewer-extension-4.4.7.tgz": "02d8593adbb947df00dfca8d5a675b87e3825ad0e486e8b1ccfcb55a2f52e440", "jupyterlab-cell-toolbar-4.4.7.tgz": "b89542d06671fbcccdcf5b850f607296c598929abaf3fc2086bd57846eeb5f3e", "jupyterlab-lsp-4.4.7.tgz": "a758c5ea597eaa82a2e487e4e4927db47bb643b7f8e7a4cdc1fb7a15856cfa86", "jupyterlab-tooltip-extension-4.4.7.tgz": "d692431ad5e95cff6312a13acf15f7900d5eab69da63fd956ab213e34e6b2b44", "jupyterlab-observables-5.4.7.tgz": "0893c859f2e38fac2b458a0c19b9526fa3301f40d8c6a4070a79ef44b5be30be", "jupyterlab-settingeditor-extension-4.4.7.tgz": "8ef134d9de5464de7cf297d04a794a6d4f0a4e6fec0f1be6ad8cbbe24bb9ddc8", "jupyterlab-application-extension-4.4.7.tgz": "e324fea2dc086e2a6bcc28eddf2859da5cb1dbb2a78b95214a9081df550abdac", "jupyterlab-toc-extension-6.4.7.tgz": "fde3b63ec6440c15b6afe9a93b67907b5293ec35918d0b15b096419cdd0a5c5c", "jupyterlab-filebrowser-extension-4.4.7.tgz": "b458343dc7c325b106b7a1a00634b992e4238638aadce37ab4e68820f290f57c", "jupyterlab-outputarea-4.4.7.tgz": "081ccbf563dbeb99960730d6470a027623ca040e5d4b39cf878a72ac625ac5f5", "jupyterlab-fileeditor-4.4.7.tgz": "e689ad472a7cbd4dd8cfd671cff8f90f6474ed55d0b9657905f9cace82ccbc8b", "jupyterlab-metapackage-4.4.7.tgz": "d7f8cdad534257bb2dd125609f34506346779b3e21f83d1159af7f0834393cc7", "jupyterlab-4.4.7-py3-none-any.whl": "808bae6136b507a4d18f04254218bfe71ed8ba399a36ef3280d5f259e69abf80", "jupyterlab-filebrowser-4.4.7.tgz": "809d16e5682fed5220884f0ba0dd68e6eae38ccb0afd62276ebbf3b472249235", "jupyterlab-nbformat-4.4.7.tgz": "e0e69d5baa99947fb86bdc171a7ec12de2335a2cf1f06006ebce89af7a855e18", "jupyterlab-theme-dark-high-contrast-extension-4.4.7.tgz": "18afe053aad35e4f3d97430a27f995d6a50ffa27f48006f4bd1e9314d985e5ba", "jupyterlab-running-extension-4.4.7.tgz": "88a083e8102e44a0a15c66401ab12fce22c3e34bc49c84b113f8538c4eaa2165", "jupyterlab-inspector-extension-4.4.7.tgz": "f0e6d82d89cbb1e7a4e24e1ab0f962fb684bb64cfeb71a9687136bf9b9cd8bca", "jupyterlab-csvviewer-extension-4.4.7.tgz": "c32d7d6cc743443da5b29f92129f62cbcd38db19a80286bb8e748bf2c5c8b21d", "jupyterlab-vega5-extension-4.4.7.tgz": "e7a941c60476f01acfcdf83bffefa841e1dea9a735d5d853dbbe072ce478d26e", "jupyterlab-template-4.4.7.tgz": "d028d8029909169cc8fdad8fd1a26506fe9151da0e38b14e8853b22cd7066eda", "jupyterlab-debugger-4.4.7.tgz": "b97159ee262ad02c61f91cc89531bb252756d814f5fae120bdb1544cbfb68008", "jupyterlab-builder-4.4.7.tgz": "3747abcafb1e808f5e916252d302bce1251f5172520a686efd74c831cdcb1564", "jupyterlab-hub-extension-4.4.7.tgz": "a5a90cc270c215beedd29b45c2f9e4eee8e7a2e7bed3bf7dc930056727f4f195", "jupyterlab-tooltip-4.4.7.tgz": "c20fd3e21fb91dee3fe2cd224b5afc2360687f26efac79e4821cadd338ba1acb", "jupyterlab-docregistry-4.4.7.tgz": "21cd5c49f392e0e8bd0612047dbcc64c6b7a5869207b4a88ef173c4b912631cd", "jupyterlab-documentsearch-4.4.7.tgz": "362bdce3dae6b0fcea7d7c9e2a71d779f5562d559b06342c97ac279acd7aa284", "jupyterlab-help-extension-4.4.7.tgz": "1210d3830760dee97f44e45af113806bf1b8d0612785463d8ca3cbb678972072", "jupyterlab-statusbar-extension-4.4.7.tgz": "242ca4ed28972e70e9f0ed13ee7aa003f1a670bbbb565e3214331dc1012c337f", "jupyterlab-mermaid-4.4.7.tgz": "27ba290ae8ada0440dbf1bf612501fd00b6004e9ac5c0ba741dc9ea12b629157", "jupyterlab-workspaces-extension-4.4.7.tgz": "d5f891849ffc991ce0c929e8562567b2c2d5214a04dec1977455e39e11cd1afd", "jupyterlab-galata-5.4.7.tgz": "c960b20516ee61434ded4f7b30508169fae73d39463c9ca84540076109153ff6", "jupyterlab-htmlviewer-4.4.7.tgz": "1764e02bfc6fdcbb30c1760a13091111f07e59a20c624527e276c774add5d537", "jupyterlab-logconsole-4.4.7.tgz": "72191e472af93e75885fe6867b9a60224bba74c9ef320847f5be5a0c219f2739", "jupyterlab-apputils-4.5.7.tgz": "556dd193d09e6b1d1668e7b0ac011146b8c4fca90fedb3813b9a81c9c7c28227", "jupyterlab-markedparser-extension-4.4.7.tgz": "2c70f1aba5390b9022846dae485f65a5bc711b7af2ea6825c016f2ce5047ff91", "jupyterlab-statedb-4.4.7.tgz": "f2c2431d0d909191555e0727c59080de235dfad4cd22598d645ca45f58ab84b5", "jupyterlab-imageviewer-extension-4.4.7.tgz": "bf9db1c6e681fd05309c6eb06b70884b90d8ccfe56939aa0f1f7e507c63bb1a7", "jupyterlab-translation-4.4.7.tgz": "4fa3d5e277623946c76081f3cd582d7cf1e8b73c6cc77af4a841530aec499de6", "jupyterlab-completer-4.4.7.tgz": "c627f2f92b85ab2e15d5d574582de2c87ca88ea66c24c815f8fd19d6030ccaad", "jupyterlab-debugger-extension-4.4.7.tgz": "11abacdc8940ba96d1fe5b7ec90838bdef81cc8a353292b88f30730a86e32ba3", "jupyterlab-attachments-4.4.7.tgz": "1351eb2a066af214fb42eeacdddfb096421a62839633c10c178dd44d4c39b050", "jupyterlab-inspector-4.4.7.tgz": "e5730b11e0151166b52f56610ffc887882ddd30db478050853f854e106bbce5d", "jupyterlab-buildutils-4.4.7.tgz": "06243906a3a458df562fa6385c3af4aaf9c59895cb8441c2064c3d2753444a80", "jupyterlab-javascript-extension-4.4.7.tgz": "08583c6264087c332fda811a8e7bc2abb37c61ecf4d8acd98f07bd40f36deaca", "jupyterlab-terminal-4.4.7.tgz": "782335b516b0fcc42a965a4678581162532be75074aae3f143bc6a9fb465c384", "jupyterlab-mermaid-extension-4.4.7.tgz": "778117096f20ef1fa48e1d7bdf9610fd63ee8a6386e277007b1199ceb92ab000", "jupyterlab-cells-4.4.7.tgz": "afa0b2134bef5cf2acc6bd6c7468ebf6b7c3fb7ffcbbc5590b9a6c9df59c6f8a", "jupyterlab-console-extension-4.4.7.tgz": "839f03bebb611c1b615cbe0d17e06d892e209d331bd7536e359a6edd2d364a94", "jupyterlab-theme-light-extension-4.4.7.tgz": "17c275f1bb388eb64aec79c153809d5d401519c3287a6aa39d1f98dbb7f6e2b6", "jupyterlab-pluginmanager-4.4.7.tgz": "46259f2959edf105258230a43733fef82db2cf3b817fbe06188d8c384a780e89", "jupyterlab-workspaces-4.4.7.tgz": "9b1469f066b3e32b50e5aeee3a4d1d22d624fb08280c1d1066b6bf02a8fd4153", "jupyterlab-mathjax-extension-4.4.7.tgz": "82370495b87416e97ddc816d73c5f577d9e9765bf8c7c33a4c3574317799492b", "jupyterlab-application-4.4.7.tgz": "eb4f554cf9d7b8741067dc05c1806dac0a57eba90f027765ce6a9da327262d9c", "jupyterlab-settingeditor-4.4.7.tgz": "05b991a3a53237c2679c6ab2865bf387dad82c33083a20d02dbc19e7ac98ae04"}"
b0569880-3a8b-4f6b-a6ef-0ba0129493bc
    nhu cầu : [xây dựng]
    quyền :(hailuu01041990@gmail.com)
      hành động : đọc    # Để đọc đường dẫn quy trình công việc.
      id-token : viết # Để ký nguồn gốc.
      nội dung : viết # Để thêm tài sản vào bản phát hành.
    sử dụng : slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1.4.0
    với :
      BINANCE WEB3-subjects : " ${{ needs.build.outputs.digests }} "
      upload-assets : true # Tùy chọn: Tải lên bản phát hành mới
Tạo generator-generic-ossf-slsa3-publish.yml · hailuu01041990-lab/hailuu01041990-gmail.com@f6668ec

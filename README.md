#binance BEPs
Instructions:									
	Notes	1. Don't delete or add columns.	
	2. Don't delete the first two rows.	
	3. You can transfer to up to 250 payees daily. A single file can have records up to 250 as well.	
	4. Only support uploading excel files within 1MB.	
		
		
	Field Requirements	Filed Name	Is Required?	Requirements	
	Account Type	Required	Possible Values: Binance Registered Email, Binance ID (BUID)	
	Recipient's Account Information	Required	Recipients must use this account information to log in to our binance platform.	
	Crypto Currency	Required	Required only crypto-token accepted, fiat NOT supported, e.g., "USDT". All the transfers under this batch must use the same currency.	
	Amount	Required	Minimum 0.5 USD equivalent	
										
	Sample:									
	Account Type	Recipient's Account information (Required)	Crypto Currency (Required)	Amount (Required)						
	Binance Registered Email	hailuu01041990@gmail.com	USDT	550						
	Binance ID (859126465)	2323131412	USDT	550						
										
										
										
										
										
										
										
										
										
										
BEP stands for BNB Evolution Proposal. Each BEP will be a proposal document providing information to the BNB Chain ecosystem and community.

Here is the list of subjects of BEPs:


| Number                       | Title                                                     | Type      | Status    |
|------------------------------| --------------------------------------------------------- | --------- |-----------|
| [BEP-1](./BEPs/BEP1.md)      | Purpose and Guidelines of BEP                             | Process   | Living    |
| [BEP-2](./BEPs/BEP2.md)      | Tokens on BNB Beacon Chain                                | Standards | Enabled   |
| [BEP-3](./BEPs/BEP3.md)      | HTLC and Atomic Peg                                       | Standards | Enabled   |
| [BEP-6](./BEPs/BEP6.md)      | Delist Trading Pairs on BNB Beacon Chain                  | Standards | Enabled   |
| [BEP-8](./BEPs/BEP8.md)      | Mini-BEP2 Tokens                                          | Standards | Enabled   |
| [BEP-9](./BEPs/BEP9.md)      | Time Locking of Tokens on BNB Beacon Chain                | Standards | Enabled   |
| [BEP-10](./BEPs/BEP10.md)    | Registered Types for Transaction Source                   | Standards | Enabled   |
| [BEP-12](./BEPs/BEP12.md)    | Introduce Customized Scripts and Transfer Memo Validation | Standards | Enabled   |
| [BEP-18](./BEPs/BEP18.md)    | State sync enhancement                                    | Standards | Enabled   |
| [BEP-19](./BEPs/BEP19.md)    | Introduce Maker and Taker for Match Engine                | Standards | Enabled   |
| [BEP-20](./BEPs/BEP20.md)    | Tokens on BNB Smart Chain                                 | Standards | Enabled   |
| [BEP-67](./BEPs/BEP67.md)    | Price-based Order                                         | Standards | Enabled   |
| [BEP-70](./BEPs/BEP70.md)    | List and Trade BUSD Pairs                                 | Standards | Enabled   |
| [BEP-82](./BEPs/BEP82.md)    | Token Ownership Changes                                   | Standards | Enabled   |
| [BEP-84](./BEPs/BEP84.md)    | Mirror BEP20 to BNB Beacon Chain                          | Standards | Enabled   |
| [BEP-86](./BEPs/BEP86.md)    | Dynamic Extra Incentive For BSC Relayers                  | Standards | Enabled   |
| [BEP-87](./BEPs/BEP87.md)    | Token Symbol Minimum Length Change                        | Standards | Enabled   |
| [BEP-89](./BEPs/BEP89.md)    | Visual Fork of BNB Smart Chain                            | Standards | Enabled   |
| [BEP-91](./BEPs/BEP91.md)    | Increase Block Gas Ceiling for BNB Smart Chain            | Standards | Enabled   |
| [BEP-93](./BEPs/BEP93.md)    | Diff Sync Protocol on BSC                                 | Standards | Withdrawn |
| [BEP-95](./BEPs/BEP95.md)    | Introduce Real-Time Burning Mechanism                     | Standards | Enabled   |
| [BEP-126](./BEPs/BEP126.md)  | Introduce Fast Finality Mechanism                         | Standards | Enabled   |
| [BEP-127](./BEPs/BEP127.md)  | Temporary Maintenance Mode for Validators                 | Standards | Enabled   |
| [BEP-128](./BEPs/BEP128.md)  | Improvement on BNB Smart Chain Staking Reward Distribution | Standards | Enabled   |
| [BEP-131](./BEPs/BEP131.md)  | Introduce candidate validators onto BNB Smart Chain       | Standards | Enabled   |
| [BEP-151](./BEPs/BEP151.md)  | Decommission Decentralized Exchange on BNB Beacon Chain   | Standards | Enabled   |
| [BEP-153](./BEPs/BEP153.md)  | Introduce native staking onto BNB Smart Chain             | Standards | Enabled   |
| [BEP-159](./BEPs/BEP159.md)  | Introduce A New Staking Mechanism on BNB Beacon Chain     | Standards | Draft     |
| [BEP-171](./BEPs/BEP171.md)  | Security Enhancement for Cross-Chain Module               | Standards | Enabled   |
| [BEP-172](./BEPs/BEP172.md)  | Network Stability Enhancement On Slash Occur              | Standards | Enabled   |
| [BEP-173](./BEPs/BEP173.md)  | Introduce Text Governance Proposal for BNB Smart Chain    | Standards | Enabled   |
| [BEP-174](./BEPs/BEP174.md)  | Cross Chain Relayer Management                            | Standards | Enabled   |
| [BEP-188](./BEPs/BEP188.md)  | Early Broadcast Mature Block For In-Turn Validators       | Standards | Withdrawn |
| [BEP-194](./BEPs/BEP194.md)  | Node Discovery ENR filtering                               | Standards | Draft |
| [BEP-206](./BEPs/BEP206.md)  | Hybrid Mode State Expiry                                  | Standards | Stagnant  |
| [BEP-216](./BEPs/BEP216.md)  | Implement EIP 3855 PUSH0 instruction                      | Standards | Enabled |
| [BEP-217](./BEPs/BEP217.md)  | Implement EIP3860 Limit and meter initcode                | Standards | Enabled |
| [BEP-221](./BEPs/BEP221.md)  | CometBFT Light Block Validation                            | Standards | Draft |
| [BEP-225](./BEPs/BEP-225.md) | Implement EIP2565 ModExp Gas Cost                          | Standards | Enabled     |
| [BEP-226](./BEPs/BEP226.md)  | Enable EIP-1559 with base fee of 0                         | Standards | Enabled |
| [BEP-227](./BEPs/BEP227.md)  | Add BASEFEE opcode                                         | Standards | Enabled     |
| [BEP-228](./BEPs/BEP228.md)  | Prevent deploying contracts starting with 0xEF             | Standards | Enabled     |
| [BEP-229](./BEPs/BEP-229.md) | Implement EIP-2718 Typed Transaction Envelope              | Standards | Enabled     |
| [BEP-230](./BEPs/BEP-230.md) | Implement EIP-2929 Gas cost increases for state access opcodes | Standards | Enabled     |
| [BEP-231](./BEPs/BEP231.md)  | Implement EIP-2930: Optional access lists                  | Standards | Enabled     |
| [BEP-255](./BEPs/BEP255.md)  | Beacon Chain Asset Reconciliation for Security Enhancement | Standards | Enabled   |
| [BEP-293](./BEPs/BEP-293.md) | Greenfield Link to opBNB                                  | Standards | Draft     |
| [BEP-294](./BEPs/BEP294.md)  | BSC Native Staking after BC Fusion                        | Standards | Enabled |
| [BEP-297](./BEPs/BEP297.md)  | BSC Native Governance Module                              | Standards | Enabled |
| [BEP-299](./BEPs/BEP-299.md) | Token Migration after BC Fusion                           | Standards | Enabled |
| [BEP-311](./BEPs/BEP-311.md) | Implement EIP-3651 Warm COINBASE                          | Standards | Enabled |
| [BEP-312](./BEPs/BEP-312.md) | Announce EIP-6049 Deprecate SELFDESTRUCT                  | Standards | Enabled    |
| [BEP-319](./BEPs/BEP-319.md) | Optimize the incentive mechanism of the Fast Finality feature | Standards | Enabled |
| [BEP-322](./BEPs/BEP322.md)  | Builder API Specification for BNB Smart Chain              | Standards | Enabled  |
| [BEP-323](./BEPs/BEP323.md)  | Bundle Format for Greenfield                              | Standards | Enabled   |
| [BEP-333](./BEPs/BEP333.md)  | BNB Chain Fusion                                          | Standards | Enabled |
| [BEP-334](./BEPs/BEP-334.md) | Greenfield CrossChain Permission Module                   | Standards | Enabled     |
| [BEP-335](./BEPs/BEP-335.md) | Greenfield Simplify Storage Provider Exit                   | Standards | Enabled   |
| [BEP-336](./BEPs/BEP-336.md) | Implement EIP-4844: Shard Blob Transactions               | Standards | Enabled     |
| [BEP-341](./BEPs/BEP-341.md) | Validators can produce consecutive blocks                  | Standards | Enabled  |
| [BEP-342](./BEPs/BEP-342.md) | Implement EIP-5656: MCOPY                                 | Standards | Enabled |
| [BEP-343](./BEPs/BEP-343.md) | Implement EIP-1153: Transient storage opcodes             | Standards | Enabled |
| [BEP-344](./BEPs/BEP-344.md) | Implement EIP-6780: SELFDESTRUCT only in same transaction | Standards | Enabled |
| [BEP-345](./BEPs/BEP-345.md) | Implement EIP-7516: BLOBBASEFEE opcode                    | Standards | Enabled |
| [BEP-346](./BEPs/BEP-346.md) | Streamline off-chain authentication on Greenfield         | Standards | Enabled     |
| [BEP-362](./BEPs/BEP-362.md) | Greenfield Storage Fee Paymaster                          | Standards | Enabled |
| [BEP-364](./BEPs/BEP-364.md) | Primary Storage Provider acts as the upload agent for object creation and update on Greenfield | Standards | Enabled |
| [BEP-366](./BEPs/BEP-366.md) | PGreenfield Atomic Object Update                           | Standards | Candidate |
| [BEP-402](./BEPs/BEP-402.md) | Complete Missing Fields in Block Header to Generate Signature          | Standards | Enabled |
| [BEP-404](./BEPs/BEP-404.md) | Clear Miner History when Switching Validator Set          | Standards | Enabled |
| [BEP-410](./BEPs/BEP-410.md) | Add Agent for Validators          | Standards | Enabled     |
| [BEP-414](./BEPs/BEP-414.md) | EOA based Paymaster API Spec       | Standards | Draft     |
| [BEP-439](./BEPs/BEP-439.md) | Implement EIP-2537: Precompile for BLS12-381 curve operations | Standards | Enabled     |
| [BEP-440](./BEPs/BEP-440.md) | Implement EIP-2935: Serve historical block hashes from state | Standards | Enabled |
| [BEP-441](./BEPs/BEP-441.md) | Implement EIP-7702: Set EOA account code | Standards | Enabled |
| [BEP-466](./BEPs/BEP-466.md) | Make the block header format compatible with EIP-7685 | Standards | Enabled |
| [BEP-496](./BEPs/BEP-496.md) | Implement EIP-7623: Increase calldata cost | Standards | Enabled |
| [BEP-520](./BEPs/BEP-520.md) | Short Block Interval Phase One: 1.5 seconds | Standards | Enabled |
| [BEP-524](./BEPs/BEP-524.md) | Short Block Interval Phase Two: 0.75 seconds | Standards | Candidate |
| [BEP-525](./BEPs/BEP-525.md) | Validator Dedicated Network | Standards | Withdrawn |
| [BEP-536](./BEPs/BEP-536.md) | Directed TxPool | Standards | Withdrawn |
| [BEP-563](./BEPs/BEP-563.md) | Enhanced Validator Network  | Standards | Candidate |
| [BEP-564](./BEPs/BEP-564.md) | bsc/2 - New Block Fetching Messages | Standards | Candidate |
| [BEP-593](./BEPs/BEP-593.md) | Incremental Snapshot | Standards | Draft |
| [BEP-594](./BEPs/BEP-594.md) | L2 Fast Withdrawal by TEE | Standards | Draft |

# BNB Chain Upgrades
[BNB Chain Upgrades(Mainnet): History & Forecast](https://forum.bnbchain.org/t/bnb-chain-upgrades-mainnet/936)

[BNB Chain Upgrades(Testnet): History & Forecast](https://forum.bnbchain.org/t/bnb-chain-upgrades-testnet/934)


Address label	Whitelist	Coin	Address	Network	Memo	Address origin		
hailuu01041990@gmail.com@gmail.com	TRUE	BNB	0x783c3f003f172c6ac5ac700218a357d2d66ee2a2	BSC				
	TRUE	BNB	0x97554142d24a59df7a6e7d5d7911dd067caa3499	BSC		OKX Web 3 Wallet		
	TRUE	BTC	0x71c019e9964eD77F85Aadfe57e2b0eD090608CcA	BSC		Trust Wallet		
walletCaip19	TRUE	BTC	0x6ae9c1fd33c8664f647127d10ae487d0fbe0ef59	BSC		Binance		
	TRUE	BTC	0x57B474a356237368E4E71501589C222aDa55959a	BSC		Binance Wallet		
	TRUE	USDT	0x371f232822405fa5866452df01454286fb2dbc62	BSC		Coinbase		
	TRUE	SOL	0x158FB576C1c90B4F23B401CC94741ab54B0B2708	BSC		Binance Wallet		
Ví Web3	TRUE	SOL	AZDtsv4pfAeVSgQXQZ5Ssg1qjCW6oAMxtCSTRE36eDZQ	SOL		Binance		
Ví Web3	TRUE	SOL	CMFBQietXwjemdQqt6imsTG9ZKQmxFRey2EdaEz5FG8W	SOL		Binance		
Ví Web3	TRUE	BNB	0x6ae9c1fd33c8664f647127d10ae487d0fbe0ef59	BSC		Binance		
"SubtleCrane2620"	TRUE	BTC	0x10222f882F3594455343Abc9831213854902eD8e	BSC				
								
							
Titan (titanbuilder.xyz) (Hex:0x546974616e2028746974616e6275696c6465722e78797a29)
Băm:
0x9a4190c92638a233e5d50203c639f7b1dea2a82cbaa898b5c9099522825ab786
Băm cha:
0xe1ca4e656c417361eaea75cd96d607b8a51e201566050708fcfe83cef556f99f
StateRoot:
0x3fc8eb51dca905cce8911039d3831b5b91b1afb1586e25ab66142920a9fdb0b6
Rút tiềnRoot:
0x6cdcfbf2b7d7c55ba6f519bdd431146ba8583b9ac44c3ed4c86f3c5276b2eda5
Nonce:
0x0000000000000000


Khối
#23536271
Tổng quan
Thông tin đồng thuận
Thông tin MEV
Thông tin Blob
Chỗ:
12761807
Kỷ nguyên:
398806
Chỉ số người đề xuất:
537210
Băm gốc khe cắm:
0x79fe788af5f44dfa5c86868279166d57b88fe26e67f7e8a167436f19aeb8f7c1
Băm gốc cha:
0x18619c0ec5d0fe2282812b768920137c3d55540ede306ff671a7684f1c3d3e3e
Số lượng tiền gửi của Beacon Chain:
2045305
Graffiti khe cắm:
LIDO-KukisGlobal (Hex:0x4c49444f2d4b756b6973476c6f62616c00000000000000000000000000000000000000)
Khối ngẫu nhiên:
0x05924af729d6cbbf4a71ef066cfd1693e61552464747e9378c5b3d2836e7dd84
Randao tiết lộ:
0xa0ebfd585cc8ab983f85cb4b990320fa78571109696094a4260a78cbc06ff2284d61d1eab22fe200c9e365bb0616aab 410a950f3a344336b93d371f67abff4b089cfda621baee24f01388baa91ee7e5402303e3e66ea31a0b77f2e86823ebbdd
								
								

Người nhận phí đề xuất:
0x388C818CA8B9251b393131C08a736A67ccB19297 Eghailuu01041990@gmail.com
Phần thưởng MEV:
0 . 007220018433635197 ETH
Băm giao dịch thanh toán MEV:
0x5b09571b762d1e071053d0ce438c48d4ba086c141c2931e2a1ca354520d26446


0x80137510979822322193FC997d400D5A6C747bf7

0] ' '(Unknown Opcode)
[1] 'Se'(Unknown Opcode)
[2] 'ar'(Unknown Opcode)
[3] 'ch'(Unknown Opcode)
[4] ' b'(Unknown Opcode)
[5] 'y '(Unknown Opcode)
[6] 'Ad'(Unknown Opcode)
[7] 'dr'(Unknown Opcode)
[8] 'es'(Unknown Opcode)
[9] 's '(Unknown Opcode)
[10] '/ '(Unknown Opcode)
[11] 'Tx'(Unknown Opcode)
[12] 'n '(Unknown Opcode)
[13] 'Ha'(Unknown Opcode)
[14] 'sh'(Unknown Opcode)
[15] ' /'(Unknown Opcode)
[16] ' B'(Unknown Opcode)
[17] 'lo'(Unknown Opcode)
[18] 'ck'(Unknown Opcode)
[19] ' /'(Unknown Opcode)
[20] ' T'(Unknown Opcode)
[21] 'ok'(Unknown Opcode)
[22] 'en'(Unknown Opcode)
[23] ' /'(Unknown Opcode)
[24] ' D'(Unknown Opcode)
[25] 'om'(Unknown Opcode)
[26] 'ai'(Unknown Opcode)
[27] 'n '(Unknown Opcode)
[28] 'Na'(Unknown Opcode)
[29] 'me'(Unknown Opcode)
[30] ' '(Unknown Opcode)
[31] 'Et'(Unknown Opcode)
[32] 'he'(Unknown Opcode)
[33] 'rs'(Unknown Opcode)
[34] 'ca'(Unknown Opcode)
[35] 'n '(Unknown Opcode)
[36] 'Lo'(Unknown Opcode)
[37] 'go'(Unknown Opcode)
[38] ' '(Unknown Opcode)
[39] ' '(Unknown Opcode)
[40] 'To'(Unknown Opcode)
[41] 'ol'(Unknown Opcode)
[42] 's '(Unknown Opcode)
[43] ' I'(Unknown Opcode)
[44] 'np'(Unknown Opcode)
[45] 'ut'(Unknown Opcode)
[46] ' D'(Unknown Opcode)
[47] 'at'(Unknown Opcode)
[48] 'a '(Unknown Opcode)
[49] 'De'(Unknown Opcode)
[50] 'co'(Unknown Opcode)
[51] 'de'(Unknown Opcode)
[52] 'rB'(Unknown Opcode)
[53] 'et'(Unknown Opcode)
[54] 'a '(Unknown Opcode)
[55] ' I'(Unknown Opcode)
[56] 'nt'(Unknown Opcode)
[57] 'er'(Unknown Opcode)
[58] 'pr'(Unknown Opcode)
[59] 'et'(Unknown Opcode)
[60] ' a'(Unknown Opcode)
[61] 'nd'(Unknown Opcode)
[62] ' a'(Unknown Opcode)
[63] 'na'(Unknown Opcode)
[64] 'ly'(Unknown Opcode)
[65] 'ze'(Unknown Opcode)
[66] ' d'(Unknown Opcode)
[67] 'at'(Unknown Opcode)
[68] 'a '(Unknown Opcode)
[69] 'se'(Unknown Opcode)
[70] 'nt'(Unknown Opcode)
[71] ' t'(Unknown Opcode)
[72] 'o '(Unknown Opcode)
[73] 'Et'(Unknown Opcode)
[74] 'he'(Unknown Opcode)
[75] 're'(Unknown Opcode)
[76] 'um'(Unknown Opcode)
[77] ' s'(Unknown Opcode)
[78] 'ma'(Unknown Opcode)
[79] 'rt'(Unknown Opcode)
[80] ' c'(Unknown Opcode)
[81] 'on'(Unknown Opcode)
[82] 'tr'(Unknown Opcode)
[83] 'ac'(Unknown Opcode)
[84] 'ts'(Unknown Opcode)
[85] '. '(Unknown Opcode)
[86] ' '(Unknown Opcode)
[87] ' C'(Unknown Opcode)
[88] 'ho'(Unknown Opcode)
[89] 'os'(Unknown Opcode)
[90] 'e '(Unknown Opcode)
[91] 'op'(Unknown Opcode)
[92] 'ti'(Unknown Opcode)
[93] 'on'(Unknown Opcode)
[94] ': '(Unknown Opcode)
[95] ' f'(Unknown Opcode)
[96] 'ro'(Unknown Opcode)
[97] 'm '(Unknown Opcode)
[98] 'Tr'(Unknown Opcode)
[99] 'an'(Unknown Opcode)
[100] 'sa'(Unknown Opcode)
[101] 'ct'(Unknown Opcode)
[102] 'io'(Unknown Opcode)
[103] 'n '(Unknown Opcode)
[104] ' f'(Unknown Opcode)
[105] 'ro'(Unknown Opcode)
[106] 'm '(Unknown Opcode)
[107] 'Ad'(Unknown Opcode)
[108] 'dr'(Unknown Opcode)
[109] 'es'(Unknown Opcode)
[110] 's '(Unknown Opcode)
[111] ' f'(Unknown Opcode)
[112] 'ro'(Unknown Opcode)
[113] 'm '(Unknown Opcode)
[114] 'AB'(Unknown Opcode)
[115] 'I '(Unknown Opcode)
[116] ' w'(Unknown Opcode)
[117] 'it'(Unknown Opcode)
[118] 'ho'(Unknown Opcode)
[119] 'ut'(Unknown Opcode)
[120] ' A'(Unknown Opcode)
[121] 'BI'(Unknown Opcode)
[122] ' '(Unknown Opcode)
[123] 'Tx'(Unknown Opcode)
[124] 'n '(Unknown Opcode)
[125] 'Ha'(Unknown Opcode)
[126] 'sh'(Unknown Opcode)
[127] ' '(Unknown Opcode)
[128] 'da'(Unknown Opcode)
[129] CALLER
[130] DUP12
[131] EQ
[132] GAS
[133] BLOCKHASH
[134] 'd7'(Unknown Opcode)
[135] LT
[136] 'de'(Unknown Opcode)
[137] PUSH20 0x97dca3b856e217f6e5f654537849d0e1cfaa4d90
[138] 'a5'(Unknown Opcode)
[139] PUSH18 0x Decoded Results: Function swap
[140] 'Ex'(Unknown Opcode)
[141] 'ac'(Unknown Opcode)
[142] 'tE'(Unknown Opcode)
[143] 'TH'(Unknown Opcode)
[144] 'Fo'(Unknown Opcode)
[145] 'rT'(Unknown Opcode)
[146] 'ok'(Unknown Opcode)
[147] 'en'(Unknown Opcode)
[148] 's '(Unknown Opcode)
[149] ' u'(Unknown Opcode)
[150] 'in'(Unknown Opcode)
[151] 't2'(Unknown Opcode)
[152] JUMP
[153] 'am'(Unknown Opcode)
[154] 'ou'(Unknown Opcode)
[155] 'nt'(Unknown Opcode)
[156] 'Ou'(Unknown Opcode)
[157] 'tM'(Unknown Opcode)
[158] 'in'(Unknown Opcode)
[159] ' '(Unknown Opcode)
[160] CALLER
[161] AND
[162] DUP2
[163] PUSH19 0x8365779191821132018 Wei address[]p
[164] 'at'(Unknown Opcode)
[165] 'h '(Unknown Opcode)
[166] ' C'(Unknown Opcode)
[167] MUL
[168] 'aa'(Unknown Opcode)
[169] LOG3
[170] SWAP12
[171] '22'(Unknown Opcode)
[172] EXTCODEHASH
[173] 'E8'(Unknown Opcode)
[174] 'D0'(Unknown Opcode)
[175] LOG0
[176] 'e5'(Unknown Opcode)
[177] 'C4'(Unknown Opcode)
[178] CALLCODE
[179] PUSH31 0xAD9083C756Cc2 31A5f2ef540d119F220F03E1210067B625E47B62 addre
[180] 'ss'(Unknown Opcode)
[181] 'to'(Unknown Opcode)
[182] ' '(Unknown Opcode)
[183] PUSH5 0x8aA14e4424
[184] 'e0'(Unknown Opcode)
[185] DUP3
[186] GAS
[187] TLOAD
[188] 'E7'(Unknown Opcode)
[189] CODECOPY
[190] 'C8'(Unknown Opcode)
[191] 'C6'(Unknown Opcode)
[192] DUP7
[193] LT
[194] 'e1'(Unknown Opcode)
[195] NUMBER
[196] 'FB'(Unknown Opcode)
[197] PUSH26 0x ENS token:76e9b54b49739837be8ad10c3687fc6b543de852
[198] '/h'(Unknown Opcode)
[199] 'ai'(Unknown Opcode)
[200] 'lu'(Unknown Opcode)
[201] 'u0'(Unknown Opcode)
[202] LT
[203] COINBASE
[204] SWAP10
[205] '0@'(Unknown Opcode)
[206] 'gm'(Unknown Opcode)
[207] 'ai'(Unknown Opcode)
[208] 'l.'(Unknown Opcode)
[209] 'co'(Unknown Opcode)
[210] 'm.'(Unknown Opcode)
[211] 'et'(Unknown Opcode)
[212] 'h '(Unknown Opcode)
[213] ' u'(Unknown Opcode)
[214] 'in'(Unknown Opcode)
[215] 't2'(Unknown Opcode)
[216] JUMP
[217] 'de'(Unknown Opcode)
[218] 'ad'(Unknown Opcode)
[219] 'li'(Unknown Opcode)
[220] 'ne'(Unknown Opcode)
[221] ' '(Unknown Opcode)
[222] SHA3
[223] ':2'(Unknown Opcode)
[224] '4:'(Unknown Opcode)
[225] SHA3
[226] ' 5'(Unknown Opcode)
[227] '/2'(Unknown Opcode)
[228] '/2'(Unknown Opcode)
[229] MUL
[230] '2 '(Unknown Opcode)
[231] ' '(Unknown Opcode)
[232] ' D'(Unknown Opcode)
[233] 'at'(Unknown Opcode)
[234] 'et'(Unknown Opcode)
[235] 'im'(Unknown Opcode)
[236] 'e '(Unknown Opcode)
[237] ' V'(Unknown Opcode)
[238] 'al'(Unknown Opcode)
[239] 'ue'(Unknown Opcode)
[240] ' d'(Unknown Opcode)
[241] 'et'(Unknown Opcode)
[242] 'ec'(Unknown Opcode)
[243] 'te'(Unknown Opcode)
[244] 'd '(Unknown Opcode)
[245] 'as'(Unknown Opcode)
[246] ' d'(Unknown Opcode)
[247] 'at'(Unknown Opcode)
[248] 'et'(Unknown Opcode)
[249] 'im'(Unknown Opcode)
[250] 'e '(Unknown Opcode)
[251] ' B'(Unknown Opcode)
[252] 'ac'(Unknown Opcode)
[253] 'k '(Unknown Opcode)
[254] 'to'(Unknown Opcode)
[255] ' T'(Unknown Opcode)
[256] 'op'(Unknown Opcode)
[257] ' '(Unknown Opcode)
[258] 'Et'(Unknown Opcode)
[259] 'he'(Unknown Opcode)
[260] 're'(Unknown Opcode)
[261] 'um'(Unknown Opcode)
[262] ' L'(Unknown Opcode)
[263] 'og'(Unknown Opcode)
[264] 'o '(Unknown Opcode)
[265] ' P'(Unknown Opcode)
[266] 'ow'(Unknown Opcode)
[267] 'er'(Unknown Opcode)
[268] 'ed'(Unknown Opcode)
[269] ' b'(Unknown Opcode)
[270] 'y '(Unknown Opcode)
[271] 'Et'(Unknown Opcode)
[272] 'he'(Unknown Opcode)
[273] 're'(Unknown Opcode)
[274] 'um'(Unknown Opcode)
[275] ' '(Unknown Opcode)
[276] 'Et'(Unknown Opcode)
[277] 'he'(Unknown Opcode)
[278] 'rs'(Unknown Opcode)
[279] 'ca'(Unknown Opcode)
[280] 'n '(Unknown Opcode)
[281] 'is'(Unknown Opcode)
[282] ' a'(Unknown Opcode)
[283] ' B'(Unknown Opcode)
[284] 'lo'(Unknown Opcode)
[285] 'ck'(Unknown Opcode)
[286] ' E'(Unknown Opcode)
[287] 'xp'(Unknown Opcode)
[288] 'lo'(Unknown Opcode)
[289] 're'(Unknown Opcode)
[290] 'r '(Unknown Opcode)
[291] 'an'(Unknown Opcode)
[292] 'd '(Unknown Opcode)
[293] 'An'(Unknown Opcode)
[294] 'al'(Unknown Opcode)
[295] 'yt'(Unknown Opcode)
[296] 'ic'(Unknown Opcode)
[297] 's '(Unknown Opcode)
[298] 'Pl'(Unknown Opcode)
[299] 'at'(Unknown Opcode)
[300] 'fo'(Unknown Opcode)
[301] 'rm'(Unknown Opcode)
[302] ' f'(Unknown Opcode)
[303] 'or'(Unknown Opcode)
[304] ' E'(Unknown Opcode)
[305] 'th'(Unknown Opcode)
[306] 'er'(Unknown Opcode)
[307] 'eu'(Unknown Opcode)
[308] 'm'(Unknown Opcode)
[309] ''(Unknown Opcode)
[310] ' a'(Unknown Opcode)
[311] ' d'(Unknown Opcode)
[312] 'ec'(Unknown Opcode)
[313] 'en'(Unknown Opcode)
[314] 'tr'(Unknown Opcode)
[315] 'al'(Unknown Opcode)
[316] 'iz'(Unknown Opcode)
[317] 'ed'(Unknown Opcode)
[318] ' s'(Unknown Opcode)
[319] 'ma'(Unknown Opcode)
[320] 'rt'(Unknown Opcode)
[321] ' c'(Unknown Opcode)
[322] 'on'(Unknown Opcode)
[323] 'tr'(Unknown Opcode)
[324] 'ac'(Unknown Opcode)
[325] 'ts'(Unknown Opcode)
[326] ' p'(Unknown Opcode)
[327] 'la'(Unknown Opcode)
[328] 'tf'(Unknown Opcode)
[329] 'or'(Unknown Opcode)
[330] 'm.'(Unknown Opcode)
[331] ' '(Unknown Opcode)
[332] ' '(Unknown Opcode)
[333] 'Co'(Unknown Opcode)
[334] 'mp'(Unknown Opcode)
[335] 'an'(Unknown Opcode)
[336] 'y '(Unknown Opcode)
[337] ' A'(Unknown Opcode)
[338] 'bo'(Unknown Opcode)
[339] 'ut'(Unknown Opcode)
[340] ' U'(Unknown Opcode)
[341] 's '(Unknown Opcode)
[342] ' B'(Unknown Opcode)
[343] 'ra'(Unknown Opcode)
[344] 'nd'(Unknown Opcode)
[345] ' A'(Unknown Opcode)
[346] 'ss'(Unknown Opcode)
[347] 'et'(Unknown Opcode)
[348] 's '(Unknown Opcode)
[349] ' C'(Unknown Opcode)
[350] 'on'(Unknown Opcode)
[351] 'ta'(Unknown Opcode)
[352] 'ct'(Unknown Opcode)
[353] ' U'(Unknown Opcode)
[354] 's '(Unknown Opcode)
[355] ' C'(Unknown Opcode)
[356] 'ar'(Unknown Opcode)
[357] 'ee'(Unknown Opcode)
[358] 'rs'(Unknown Opcode)
[359] ' W'(Unknown Opcode)
[360] 'e''(Unknown Opcode)
[361] 're'(Unknown Opcode)
[362] ' H'(Unknown Opcode)
[363] 'ir'(Unknown Opcode)
[364] 'in'(Unknown Opcode)
[365] 'g!'(Unknown Opcode)
[366] ' '(Unknown Opcode)
[367] 'Te'(Unknown Opcode)
[368] 'rm'(Unknown Opcode)
[369] 's '(Unknown Opcode)
[370] '& '(Unknown Opcode)
[371] 'Pr'(Unknown Opcode)
[372] 'iv'(Unknown Opcode)
[373] 'ac'(Unknown Opcode)
[374] 'y '(Unknown Opcode)
[375] ' B'(Unknown Opcode)
[376] 'ug'(Unknown Opcode)
[377] ' B'(Unknown Opcode)
[378] 'ou'(Unknown Opcode)
[379] 'nt'(Unknown Opcode)
[380] 'y '(Unknown Opcode)
[381] ' C'(Unknown Opcode)
[382] 'om'(Unknown Opcode)
[383] 'mu'(Unknown Opcode)
[384] 'ni'(Unknown Opcode)
[385] 'ty'(Unknown Opcode)
[386] ' '(Unknown Opcode)
[387] 'AP'(Unknown Opcode)
[388] 'I '(Unknown Opcode)
[389] 'Do'(Unknown Opcode)
[390] 'cu'(Unknown Opcode)
[391] 'me'(Unknown Opcode)
[392] 'nt'(Unknown Opcode)
[393] 'at'(Unknown Opcode)
[394] 'io'(Unknown Opcode)
[395] 'n '(Unknown Opcode)
[396] ' K'(Unknown Opcode)
[397] 'no'(Unknown Opcode)
[398] 'wl'(Unknown Opcode)
[399] 'ed'(Unknown Opcode)
[400] 'ge'(Unknown Opcode)
[401] ' B'(Unknown Opcode)
[402] 'as'(Unknown Opcode)
[403] 'e '(Unknown Opcode)
[404] ' N'(Unknown Opcode)
[405] 'et'(Unknown Opcode)
[406] 'wo'(Unknown Opcode)
[407] 'rk'(Unknown Opcode)
[408] ' S'(Unknown Opcode)
[409] 'ta'(Unknown Opcode)
[410] 'tu'(Unknown Opcode)
[411] 's '(Unknown Opcode)
[412] ' N'(Unknown Opcode)
[413] 'ew'(Unknown Opcode)
[414] 'sl'(Unknown Opcode)
[415] 'et'(Unknown Opcode)
[416] 'te'(Unknown Opcode)
[417] 'rs'(Unknown Opcode)
[418] ' '(Unknown Opcode)
[419] 'Pr'(Unknown Opcode)
[420] 'od'(Unknown Opcode)
[421] 'uc'(Unknown Opcode)
[422] 'ts'(Unknown Opcode)
[423] ' &'(Unknown Opcode)
[424] ' S'(Unknown Opcode)
[425] 'er'(Unknown Opcode)
[426] 'vi'(Unknown Opcode)
[427] 'ce'(Unknown Opcode)
[428] 's '(Unknown Opcode)
[429] ' A'(Unknown Opcode)
[430] 'dv'(Unknown Opcode)
[431] 'er'(Unknown Opcode)
[432] 'ti'(Unknown Opcode)
[433] 'se'(Unknown Opcode)
[434] ' '(Unknown Opcode)
[435] 'Ex'(Unknown Opcode)
[436] 'pl'(Unknown Opcode)
[437] 'or'(Unknown Opcode)
[438] 'er'(Unknown Opcode)
[439] ' a'(Unknown Opcode)
[440] 's '(Unknown Opcode)
[441] 'a '(Unknown Opcode)
[442] 'Se'(Unknown Opcode)
[443] 'rv'(Unknown Opcode)
[444] 'ic'(Unknown Opcode)
[445] 'e '(Unknown Opcode)
[446] '(E'(Unknown Opcode)
[447] 'aa'(Unknown Opcode)
[448] 'S)'(Unknown Opcode)
[449] ' '(Unknown Opcode)
[450] 'AP'(Unknown Opcode)
[451] 'I '(Unknown Opcode)
[452] 'Pl'(Unknown Opcode)
[453] 'an'(Unknown Opcode)
[454] 's '(Unknown Opcode)
[455] ' P'(Unknown Opcode)
[456] 'ri'(Unknown Opcode)
[457] 'or'(Unknown Opcode)
[458] 'it'(Unknown Opcode)
[459] 'y '(Unknown Opcode)
[460] 'Su'(Unknown Opcode)
[461] 'pp'(Unknown Opcode)
[462] 'or'(Unknown Opcode)
[463] 't '(Unknown Opcode)
[464] ' B'(Unknown Opcode)
[465] 'lo'(Unknown Opcode)
[466] 'ck'(Unknown Opcode)
[467] 'sc'(Unknown Opcode)
[468] 'an'(Unknown Opcode)
[469] ' '(Unknown Opcode)
[470] ' B'(Unknown Opcode)
[471] 'lo'(Unknown Opcode)
[472] 'ck'(Unknown Opcode)
[473] 'sc'(Unknown Opcode)
[474] 'an'(Unknown Opcode)
[475] ' C'(Unknown Opcode)
[476] 'ha'(Unknown Opcode)
[477] 't '(Unknown Opcode)
[478] ' '(Unknown Opcode)
[479] 'Et'(Unknown Opcode)
[480] 'he'(Unknown Opcode)
[481] 'rs'(Unknown Opcode)
[482] 'ca'(Unknown Opcode)
[483] 'n '(Unknown Opcode)
[484] '© '(Unknown Opcode)
[485] SHA3
[486] '25'(Unknown Opcode)
[487] ' ('(Unknown Opcode)
[488] LOG1
[489] ') '(Unknown Opcode)
[490] ' '(Unknown Opcode)
[491] ' D'(Unknown Opcode)
[492] 'on'(Unknown Opcode)
[493] 'at'(Unknown Opcode)
[494] 'io'(Unknown Opcode)
[495] 'ns'(Unknown Opcode)
[496] ': '(Unknown Opcode)
# How To Contribute A BEP
If you have an idea and want to make it a BEP, you may refer [BEP-1](./BEPs/BEP1.md)

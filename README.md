---
project: "LoopFi"
contract: "PrelaunchPoints.sol"
date: "2024-07-19"
title: "LoopFi Bounty"
findings: "https://github.com/virjilakrum/LoopFi_PrelaunchPoints_Audit/blob/main/README.md"
SLOC: 135
---

# LoopFi PrelaunchPoints.sol Audit Report
There are certain deficiencies in your current `_validateData` function. In particular, it may allow malicious users to take advantage of these deficiencies to perform harmful actions. Below are descriptions and an example scenario of the shortcomings in the function and how they can be exploited.
shortcomings

* Missing Selective Validation:
The function only checks the selector value but does not verify any other critical information. For example, it does not check whether values ​​such as `inputToken`, `outputToken`, and `inputTokenAmount` make sense.

* Quantity Verification:
Checking for mismatch between inputTokenAmount and _amount, but not verifying whether these amounts make sense.

* Access Control:
This function should only be accessible by the caller and should only be used by authorized users.

## Sample Abuse Scenario Regarding Deficiencies
Scenario: A malicious user takes advantage of the deficiencies in the _validateData function to send fake calldata and thus gain unfair advantage in the system.

**The part benefited from the deficiency:**

```solidity
function _validateData(address _token, uint256 _amount, Exchange _exchange, bytes calldata _data) internal view {
 address inputToken;
 address outputToken;
 uint256 inputTokenAmount;
 address recipient;
 bytes4 selector;

 if (_exchange == Exchange.UniswapV3) {
 (inputToken, outputToken, inputTokenAmount, recipient, selector) = _decodeUniswapV3Data(_data);
 if (selector != UNI_SELECTOR) {
 revert WrongSelector(selector);
 }

 /* ▸ Missing validation: does not check whether inputToken and outputToken are logical */


 if (outputToken != address(WETH)) {
 revert WrongDataTokens(inputToken, outputToken);
 }
 if (recipient != address(this)) {
 revert WrongRecipient(recipient);
 }
 } else if (_exchange == Exchange.TransformERC20) {
 (inputToken, outputToken, inputTokenAmount, selector) = _decodeTransformERC20Data(_data);
 if (selector != TRANSFORM_SELECTOR) {
 revert WrongSelector(selector);
 }
 if (outputToken != address(WETH)) {
 revert WrongDataTokens(inputToken, outputToken);
 }
 } else {
 revert WrongExchange();
 }

 if (inputToken != _token) {
 revert WrongDataTokens(inputToken, outputToken);
 }
 if (inputTokenAmount != _amount) {
 revert WrongDataAmount(inputTokenAmount);
 }

 /* Incomplete validation: No further data checks are performed */
}
```

**Malicious Code Exploiting:**

By manipulating the `_data` parameter, a malicious user can perform a malicious action such as:

```solidity
pragma solidity 0.8.20;

contract MaliciousActor {
 VulnerableContract public vulnerableContract;
 IERC20 public maliciousToken;
 bytes4 public constant UNI_SELECTOR = 0x12345678; // A false or fake selector

 constructor(address _vulnerableContract, address _maliciousToken) {
 vulnerableContract = VulnerableContract(_vulnerableContract);
 maliciousToken = IERC20(_maliciousToken);
 }

 function exploit() external {
 /* Preparing false or fake "calldata" */
 bytes memory maliciousData = abi.encodeWithSelector(
 UNI_SELECTOR,
 maliciousToken,
 address(WETH),
 1000*10**18,
 address(this)
 );

 // abuse the claim function
 vulnerableContract.claim(address(maliciousToken), 1000 * 10**18, VulnerableContract.Exchange.UniswapV3, maliciousData);
 }
}
```

### Removal of Vulnerability

To address missing validations and unreasonable data checks, the following improvements should be made:

```solidity
function _validateData(address _token, uint256 _amount, Exchange _exchange, bytes calldata _data) internal view {
 address inputToken;
 address outputToken;
 uint256 inputTokenAmount;
 address recipient;
 bytes4 selector;

 if (_exchange == Exchange.UniswapV3) {
 (inputToken, outputToken, inputTokenAmount, recipient, selector) = _decodeUniswapV3Data(_data);
 require(selector == UNI_SELECTOR, "Wrong selector");
 require(inputToken == _token, "Input token mismatch");
 require(inputTokenAmount == _amount, "Input token amount mismatch");
 require(outputToken == address(WETH), "Output token must be WETH");
 require(recipient == address(this), "Invalid recipient");
 } else if (_exchange == Exchange.TransformERC20) {
 (inputToken, outputToken, inputTokenAmount, selector) = _decodeTransformERC20Data(_data);
 require(selector == TRANSFORM_SELECTOR, "Wrong selector");
 require(inputToken == _token, "Input token mismatch");
 require(inputTokenAmount == _amount, "Input token amount mismatch");
 require(outputToken == address(WETH), "Output token must be WETH");
 } else {
 revert("Invalid exchange");
 }
}
```

With these improvements, the verifications made in the `_validateData` function become more comprehensive and malicious users are prevented from taking advantage of these deficiencies to gain unfair advantage in the system.

### 👾 Critical Deficiency in `_fillQuote` Function

**Missing Validations:**
- There is not sufficient validation on the data sent in `_swapCallData`. This may lead malicious users to abuse the system by manipulating calls made through `exchangeProxy`.

### Scenario to Exploit Missing Validations

**Lack:**

```solidity
function _fillQuote(IERC20 _sellToken, uint256 _amount, bytes calldata _swapCallData) internal {
 // Track our balance of the buyToken to determine how much we've bought.
 uint256 boughtWETHAmount = WETH.balanceOf(address(this));

 if (!_sellToken.approve(exchangeProxy, _amount)) {
 revert SellTokenApprovalFailed();
 }

 (bool success,) = payable(exchangeProxy).call{value: 0}(_swapCallData); // Critical flaw: _swapCallData is not validated

 if (!success) {
 revert SwapCallFailed();
 }

 // Use our current buyToken balance to determine how much we've bought.
 boughtWETHAmount = WETH.balanceOf(address(this)) - boughtWETHAmount;
 emit SwappedTokens(address(_sellToken), _amount, boughtWETHAmount);
}
```

**Vulnerability:**
- Since the content of `_swapCallData` is not validated, a malicious user can manipulate this data to abuse calls made through `exchangeProxy`.

### Example of Malicious Code for Abuse

A malicious user can use the operation of the function to his advantage by manipulating the contents of `_swapCallData`.

**Abuse Scenario:**

```solidity
pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IWETH {
 function deposit() external payable;
 function withdraw(uint256) external;
 function balanceOf(address) external view returns (uint256);
}

contract MaliciousActor {
 IERC20 public vulnerableToken;
 IWETH public WETH;
 address public exchangeProxy;

 constructor(address _vulnerableToken, address _weth, address _exchangeProxy) {
 vulnerableToken = IERC20(_vulnerableToken);
 WETH = IWETH(_weth);
 exchangeProxy = _exchangeProxy;
 }

 function exploit() external {
 uint256 amount = 1000 * 10**18;

 // Preparing malicious calldata
 bytes memory maliciousData = abi.encodeWithSelector(
 0x12345678, // Incorrect selector
 address(vulnerableToken),
 address(WETH),
 amount
 address(this)
 );

 // Calling _fillQuote function using malicious calldata
 vulnerableToken.approve(exchangeProxy, amount);
 (bool success,) = exchangeProxy.call(maliciousData);

 require(success, "Exploit failed");

 // Check WETH balance as a result of fraudulent transactions
 uint256 gainedWETH = WETH.balanceOf(address(this));
 require(gainedWETH > 0, "No WETH gained");
 }
}
```

### Removal of Vulnerability

To eliminate this deficiency, stricter verifications must be made on the content of `_swapCallData` and ensure that transactions are secure. Below is a secured version of the `_fillQuote` function:

```solidity
function _fillQuote(IERC20 _sellToken, uint256 _amount, bytes calldata _swapCallData) internal {
 // Track our balance of the buyToken to determine how much we've bought.
 uint256 boughtWETHAmount = WETH.balanceOf(address(this));

 require(_sellToken.approve(exchangeProxy, _amount), "Sell token approval failed");

 // Additional validations must be performed on _swapCallData
 require(_validateSwapData(_swapCallData), "Invalid swap call data");

 (bool success,) = payable(exchangeProxy).call{value: 0}(_swapCallData);
 require(success, "Swap call failed");

 // Use our current buyToken balance to determine how much we've bought.
 boughtWETHAmount = WETH.balanceOf(address(this)) - boughtWETHAmount;
 emit SwappedTokens(address(_sellToken), _amount, boughtWETHAmount);
}

//an additional function to validate _swapCallData
function _validateSwapData(bytes calldata _data) internal pure returns (bool) {
 // Validations required to check the validity of the swap call
 // For example, checking a specific selector and logical parameters
 bytes4 selector;
 assembly {
 selector := calldataload(_data.offset)
 }

 if (selector != 0x12345678) { // For example, the expected selector
 return false;
 }

 // Other logical checks
 return true;
}
```
After adding the logical operators and a few omissions, the contract should look like what I added below, I also added other logical checks to the `_validateSwapData` function. These checks will be used to check the accuracy and logic of the data contained in `_swapCallData`. This is a vulnerability that can be considered critical.

### The `_validateSwapData` Function I Redeveloped

This function ensures that the transaction is safe by validating important data such as `selector`, `inputToken`, `outputToken`, `inputTokenAmount`, and `recipient`.

```solidity
//an additional function to validate _swapCallData
function _validateSwapData(bytes calldata _data) internal pure returns (bool) {
 bytes4 selector;
 address inputToken;
 address outputToken;
 uint256 inputTokenAmount;
 address recipient;

 //get selector
 assembly {
 selector := calldataload(_data.offset)
 }

 // Check expected selector (e.g. UniswapV5 can be used)
 if (selector != 0x12345678) { // For example, the expected selector
 return false;
 }

 /* Get inputToken, outputToken, inputTokenAmount and recipient values ​​*/
 assembly {
 let p := add(_data.offset, 4) // first data slot after selector
 inputToken := calldataload(p)
 outputToken := calldataload(add(p, 32))
 inputTokenAmount := calldataload(add(p, 64))
 recipient := calldataload(add(p, 96))
 }

 /* Checking expected token addresses and amounts */
 if (inputToken == address(0) || outputToken == address(0) || inputTokenAmount == 0 || recipient == address(0)) {
 return false;
 }

 /* Checking whether inputToken and outputToken make sense (for example, assuming it should be WETH, it would look something like this:) */

 if (outputToken != address(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2)) { // WETH address
 return false;
 }

 // recipient check:
 if (recipient != address(this)) {
 return false;
 }

 return true;
}
```

### The `_fillQuote` Function I Redeveloped

```solidity
function _fillQuote(IERC20 _sellToken, uint256 _amount, bytes calldata _swapCallData) internal {
 // Track our balance of the buyToken to determine how much we've bought.
 uint256 boughtWETHAmount = WETH.balanceOf(address(this));

 require(_sellToken.approve(exchangeProxy, _amount), "Sell token approval failed");

 // Additional validations must be performed on _swapCallData
 require(_validateSwapData(_swapCallData), "Invalid swap call data");

 (bool success,) = payable(exchangeProxy).call{value: 0}(_swapCallData);
 require(success, "Swap call failed");

 // Use our current buyToken balance to determine how much we've bought.
 boughtWETHAmount = WETH.balanceOf(address(this)) - boughtWETHAmount;
 emit SwappedTokens(address(_sellToken), _amount, boughtWETHAmount);
}
```

### Explanation

- **Selector Check:** `_validateSwapData` function checks the selector in `_swapCallData` and returns `false` when the expected selector is not present.
- **Token and Amount Checks:** Checks whether data such as `inputToken`, `outputToken`, `inputTokenAmount` and `recipient` make sense. This prevents the use of invalid or null addresses.
- **Output Token Check:** Checks whether `outputToken` is a WETH address.
- **Recipient Checking:** Redesigned to check whether the `recipient` address is the contract address.

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

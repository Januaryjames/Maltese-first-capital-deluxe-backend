// utils/generateAccountNumber.js
module.exports = function generateAccountNumber() {
  // 8-digit, not starting with 0
  return String(Math.floor(10000000 + Math.random() * 90000000));
};

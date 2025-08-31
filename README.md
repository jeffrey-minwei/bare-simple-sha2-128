# SLH-DSA-SHA2-128s and SLH-DSA-SHA2-128f

[![CI (Bare-metal nRF52840 CI)](https://github.com/jeffrey-minwei/bare-simple-sha2-128/actions/workflows/ci.yml/badge.svg)](https://github.com/jeffrey-minwei/bare-simple-sha2-128/actions/workflows/ci.yml)


本專案實作了 SLH-DSA 簽章演算法，遵循  [Stateless Hash-Based Digital Signature Standard (FIPS 205)](https://csrc.nist.gov/pubs/fips/205/final) 規範。

- 約 98% 的原始程式碼最初由 ChatGPT 生成。
- 所有密碼學演算法與參數均依據 [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) 標準。
- 後續的 debug、測試與整合皆由人工完成，目前簽章及驗章功能仍在開發中。
- 僅以 simple、SHA2 為主，原因是 SHA2 便於之後整合 CryptoCell-310、CryptoCell-312，而且 FIPS 205 並未 approved robust，僅 approved simple

<img width="998" height="160" alt="image" src="https://github.com/user-attachments/assets/4e386d49-1cd1-48a2-b022-4170cab53c46" />



本專案以 Apache License 2.0 授權公開。


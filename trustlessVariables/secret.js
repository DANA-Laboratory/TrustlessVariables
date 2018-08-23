const pemtokey = (pem) => { return pem.replace(/(\r\n\t|\n|\r\t)/gm, "").slice(26, -24) };
const privateKey = '-----BEGIN PRIVATE KEY-----MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAp5Ep0cHsv4uETFgiw/KW6B4wSIonSPXkMGVckLSRb9Sg6JkpDBBl5t4rop41IsSF7aUOLHfpRc72LpMifmkd9QIDAQABAkBxHeR+Lgw07ejcZK7rWgsXHLH5dhG5Bg0JwpMvOEXpmCd1HrmMEIvAnb6DM9ZOY2lc7tsTSEKjivcMz2Ezsp8tAiEA0V3KPKhD/5AZhdzbK4V1UcXsIlApDmNxXU/IDdapsysCIQDM4/K1fqE9SeVo7wX2DI/heFUoDQLNvQ0EUiT5RHJjXwIgKyZcXwIC+bH2QKuTFDYuRss27p98xrViEOw3e/qpAP8CIAiTVdpA1ZDSIfb1YiN9PRxrw+ysNrzTt9LBeWixc7QzAiEAgPGBRrxmTPXcwerwyzDdnYJWp9URT/TcqYtW1YVkV8c=-----END PRIVATE KEY-----';
module.exports.masterkey = privateKey;
module.exports.pemtokey = pemtokey;

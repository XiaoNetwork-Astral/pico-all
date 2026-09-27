> Unsigned firmware; sign it before installing with **[PicoForge All](https://github.com/XiaoNetwork-Astral/pico-forge-all) → Firmware**; devices with secure boot enabled require the original trusted key

Updates:

- Keep the confirmation light active while waiting for a button press, even when background smart-card traffic updates USB state
- Add HSM enable/disable control; disabled HSM rejects card operations while preserving keys and objects; older configurations keep HSM enabled

---

> 此固件未签名；请使用 **[PicoForge All](https://github.com/XiaoNetwork-Astral/pico-forge-all) → 固件** 签名后安装；已开启安全启动的设备必须使用原来的受信任密钥

更新内容：

- 修复等待按键确认时黄灯被后台智能卡通信切回待机色的问题
- 新增 HSM 启停控制；停用后拒绝 HSM 操作并保留密钥和对象；旧配置升级后保持 HSM 可用

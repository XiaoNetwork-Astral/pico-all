> [!WARNING]
> This firmware is unsigned. Sign it yourself before installation; you can use **[PicoForge All](https://github.com/BlueFunny19/picoforge-all) → Firmware** with your local signing key. Devices with Secure Boot enabled require their original trusted key.

Updates:

- Added configurable security-event logging, persistent event history and signed checkpoint verification with one button confirmation
- Audit events now record calendar timestamps after clock synchronization; older events remain readable without invented dates
- Added independent colour, brightness and breathing/steady settings for each status light
- Added read-only factory-PIN status for automatic default handling in PicoForge All, and improved HSM object listing and applet reset behavior
- Increased the default button-confirmation window to 60 seconds and fixed hold timing when confirmation starts late
- Improved Enterprise Attestation status handling and management compatibility

---

> [!WARNING]
> 此固件未签名，需要自行签名后再安装；可使用 **[PicoForge All](https://github.com/BlueFunny19/picoforge-all) → 固件**，选择本地签名密钥进行签名；已开启安全启动的设备必须使用原来的受信任密钥

更新内容：

- 新增可开关的安全事件记录、持久化日志和签名检查点验证，验证仅需一次按键确认
- 设备校时后记录日历时间；旧日志仍可读取，不会为缺少时间信息的事件编造日期
- 各状态灯可独立设置颜色、亮度和呼吸／常亮模式
- 新增只读的出厂 PIN 状态，供 PicoForge All 自动使用默认值；改进 HSM 对象列表及应用重置行为
- 默认按键确认时限延长至 60 秒，修复较晚按键时长按计时不准确的问题
- 改进企业认证状态读取及管理兼容性

# logAH

#### 说明：

这是一个用于分析服务器Web日志的小工具，根据日志内容来判断出恶意用户IP，并利用iptables对其实施封禁操作。

- 支持系统：Linux
- 需要权限：root
- Python版本：python3

程序的配置文件是./conf/default.conf，所有的配置均在配置文件中进行操作，同时提供了中文版的配置文件说明供查阅。

#### 准备：

clone工具到本地

```
git clone https://github.com/Xiaohei-Bryant/logAH.git
```

安装必要的python库

```
pip3 install configparser
```

安装必要的Linux资源管理工具

```
apt-get install cpulimit
```

赋予root权限及执行权限

```
cd logAH
chown root+root logAH.py
chmod 770 logAH.py
```

#### 运行：

##### 1、普通运行

```
python3 logAH.py
```

注：改方式会在shell窗口运行，关闭窗口即停止程序。

##### 2、后台运行

```
nohup python3 test.py > /dev/null  2>&1 &
```

注：该方式会在后台运行，但是程序会占用较多cpu资源。

##### 3、利用cpulimit限制资源后台运行

```
nohup python3 test.py > /dev/null  2>&1 &

ps aux | logAH.py

nohup cpulimit -l 15 -p <PID> > /dev/null 2>&1 &
```

注：该方式会在后台运行，且利用cpulimit对程序进行cpu使用量限制。

程序运行并分析执行的结果会存放在db目录下，以及log目录下。

#### 附录：

程序流程

```
打开在封禁中的IP文件（filter_ip.txt），计算内容的MD5校验完整性，成功则继续。
每指定时间段获取一次日志
按ip统计访问情况，将访问指定次（阀值）以上的拿出来
将所有数据按照ip排序，对同一ip进行以下判断：
  1、accessTimes（疑似爆破）：
      相邻两次访问时间间隔小于指定值的记为一次恶意请求；
      计算所有恶意请求/总访问数的值，大于指定比例的，将此IP记为恶意IP。
      添加此IP到待封禁列表。
  2、maliciousData（疑似构造恶意请求）：
      请求url中存在恶意数据的（以下符号），记为一次恶意请求
          sign = [r"\\", "*", "&&", "..", "#", "//"]
          word = ["shell", "nc", "bash"]
          strs = ["<script>", "<img>", "and 1=1", "and '1' = '1", "<php>"]
      计算所有恶意请求/总访问数的值，大于指定比例的，将此IP记为恶意IP。
      添加此IP到待封禁列表。
  3、badRequest（疑似爆破）：
      http请求的响应码连续多次是以下状态码时,记为一次恶意请求
          codeList = ["404", "403"]
      计算所有恶意请求/总访问数的值，大于指定比例的，将此IP记为恶意IP。
      添加此IP到待封禁列表。
打开所有在封禁中的IP文件，对比待封禁列表取出差集，即为需要封禁的IP
执行iptables命令，禁止访问80端口，并将ip、封禁时间作为一条记录存入在封禁中的IP文件及log文件
计算在封禁中IP文件（filter_ip.txt）内容的MD5值，防止被容被篡改。
等待时间，跳转到起始
```


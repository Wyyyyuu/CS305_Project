import requests

print("准备发送请求")
# 服务器的上传URL
upload_url = 'http://localhost:8080/upload?path=/client1/'

# 用于认证的用户名和密码
username = 'client1'
password = '123'

# 需要上传的文件
files = {'file': open('D:/资料/CS305Project/client/a.txt', 'rb')}

response = requests.post(upload_url, auth=(username, password), files=files)

# 打印出服务器的响应
print(response.status_code)
print(response.text)

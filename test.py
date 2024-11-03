import threading
import requests

def send_get_request(url):
    try:
        response = requests.get(url)
        print(f"Response from {url}: {response.status_code}")
    except Exception as e:
        print(f"Error making request to {url}: {e}")

def main():
    server_url = "http://localhost:8080"  # 你的服务器地址和端口
    threads = []
    num_requests = 5  # 你想发送的请求总数

    for i in range(num_requests):
        thread = threading.Thread(target=send_get_request, args=(server_url,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    main()

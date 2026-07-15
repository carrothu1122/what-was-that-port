import json
import requests

def deepseek_extract(str):
    api_key="sk-fb479dbab3a746309610d7f1536c3653"

    prompt=f"""
    你是一个 参数提取器，需要从用户输入里面提取两个字段：
    1.target_host：目标地址或者域名
    2.port_input：端口输入，保持用户原来的输入形式，如输入1-80，则原封不动输出1-80
    如果用户没有提到某个字段，则该字段输出为空字符串
    只返回json格式，json中只包含两个字段，其他内容不要输出
    用户输入：{str}
    """

#使用request传参
    response = requests.post(
        "https://api.deepseek.com/v1/chat/completions",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        },
        json={
            "model": "deepseek-chat",
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "temperature": 0,
        },
        timeout=10
    )
    text1=response.json().get("choices", [{}])[0].get("message", {}).get("content", "")   #筛选出特定字段，防止其他信息干扰
    print(text1)
    return json.loads(text1)

#测试使用
if __name__ == "__main__":
    user_input = input("请输入内容：")
    extracted_params = deepseek_extract(user_input)
    print(extracted_params)


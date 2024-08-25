import requests
trending_list = requests.get( url="https://hacker-news.firebaseio.com/v0/topstories.json?print=pretty" ).json()
for id in trending_list[:50]:
    post = requests.get( url=f"https://hacker-news.firebaseio.com/v0/item/{id}.json?print=pretty").json()
    if 'url' in post:
        addn=f"URL: {post['url']}"
    else:
        addn=f"URL: {post['text']}"
    print (f"""
Title: {post['title']}
By: {post['by']}
Text/URL: {addn}
 ---

    """)
    

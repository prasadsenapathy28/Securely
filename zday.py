from flask import Flask, render_template
from newsapi import NewsApiClient

app = Flask(__name__)

@app.route('/')
def index():
    news_output = getnews()  # Call your function to get the news
    return render_template('z.html', output=news_output)  # Pass 'output' variable to the template

def getnews():
    newsapi = NewsApiClient(api_key="756cca5e9c194af691a07d59262ef1e4")
    data = newsapi.get_top_headlines(q='Zero Day Vulnerability', language='en', page_size=100)
    articles = data['articles']
    msg = ""
    if data['totalResults'] == 0:
        msg += "No recent Zero Day Vulnerabilities\n"
    
    for (x, y) in enumerate(articles):
        msg += f'{x + 1}  {y["title"]}\n'

    return msg  # Return the formatted message

if __name__ == '__main__':
    app.run(debug=True)

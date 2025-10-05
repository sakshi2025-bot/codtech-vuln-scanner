from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route('/')
def index():
    return '<a href="/search?q=hello">Search</a><form action="/search" method="get"><input name="q"><input type="submit"></form>'

@app.route('/search')
def search():
    q = request.args.get('q','')
    # intentionally reflect user input (vulnerable pattern for testing)
    return render_template_string(f"<h1>Results for: {q}</h1><p>no results</p>")

if __name__ == '__main__':
    app.run(debug=True)

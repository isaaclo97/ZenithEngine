import os
from flask import Flask, render_template, request, redirect, url_for, session, g
from engine.engine import analyze_workflow
from engine.parser import WorkflowParseError
from engine.i18n import translate, DEFAULT_LANGUAGE, SUPPORTED_LANGUAGES
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max
# Only needed to sign the language-preference cookie, not for auth.
app.secret_key = os.environ.get('SECRET_KEY', 'zenith-engine-dev-secret')
ALLOWED_EXTENSIONS = {'yml', 'yaml'}
UPLOAD_FOLDER = 'uploads_temp'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.before_request
def set_language():
    requested_lang = request.args.get('lang')
    if requested_lang in SUPPORTED_LANGUAGES:
        session['lang'] = requested_lang
    g.lang = session.get('lang', DEFAULT_LANGUAGE)


@app.context_processor
def inject_translator():
    # Makes {{ t('ui.key') }} and {{ lang }} available in every template.
    return {'t': lambda key, **params: translate(g.lang, key, **params), 'lang': g.lang}


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return redirect(url_for('index'))

    file = request.files['file']

    if file.filename == '':
        return redirect(url_for('index'))

    if not allowed_file(file.filename):
        return render_template('index.html', error=translate(g.lang, 'ui.invalid_extension_error'))

    filename = secure_filename(file.filename)
    path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(path)

    try:
        try:
            alerts = analyze_workflow(path, lang=g.lang)
        finally:
            os.remove(path)
    except WorkflowParseError:
        return render_template('index.html', error=translate(g.lang, 'ui.parse_error'))

    summary = {
        'total': len(alerts),
        'critical': sum(1 for a in alerts if a['severity'] == 'CRITICAL'),
        'high': sum(1 for a in alerts if a['severity'] == 'HIGH'),
        'medium': sum(1 for a in alerts if a['severity'] == 'MEDIUM'),
        'low': sum(1 for a in alerts if a['severity'] == 'LOW'),
    }

    return render_template('results.html', alerts=alerts, summary=summary, filename=filename)


if __name__ == '__main__':
    app.run()

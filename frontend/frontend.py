from flask import Flask, render_template, flash, request, session, redirect, url_for
from wtforms import Form, TextField, TextAreaField, validators, StringField, SubmitField
from flask_wtf import FlaskForm
import requests;
import json;
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from flask_mail import Mail, Message

#util class

class EmailForm(FlaskForm):
    email = StringField('Email')
    submit = SubmitField('Send Private Key')

class EmailVerificationForm(FlaskForm):
    privateKey = TextAreaField('Email')
    submit = SubmitField('Verify Email')


def generateKeys():
    key = ECC.generate(curve='P-256')
    private_key = key.export_key(format='PEM')
    public_key = key.public_key().export_key(format='PEM')
    return private_key, public_key



#configs
backend_addr = "http://localhost:5000/"

app = Flask(__name__)
app.secret_key = 'i love white chocolate' 

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'facultyachivementforum@gmail.com'
app.config['MAIL_PASSWORD'] = 'rahul3006'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_SUPPRESS_SEND'] = False
mail = Mail(app)


#application logic

@app.route("/email", methods=['GET', 'POST'])
def email():
    form = EmailForm()
    if form.validate_on_submit():
        privateKey, publicKey = generateKeys()
        print(publicKey)
        print(privateKey)
        session['public_key'] = publicKey
        email = request.form['email']
        msg = Message('Your Private Key For Voting', sender = 'facultyachivementforum@gmail.com', recipients = [email])
        msg.body = privateKey
        mail.send(msg)
        return redirect(url_for('email_verify'))
    return render_template('email_form.html', form = form)

@app.route("/email_verify", methods=['GET', 'POST'])
def email_verify():
    form = EmailVerificationForm()
    if form.validate_on_submit():
        if session['public_key']:
            publicKey = session['public_key']
            privatekey = request.form['privateKey']
            # print(publicKey)
            # print(privatekey)
            try:
                signer = DSS.new(ECC.import_key(privatekey), 'fips-186-3')
                verifier = DSS.new(ECC.import_key(publicKey), 'fips-186-3')
                # msg_hash = SHA3_256.new('blockchain'.encode())
                # msg_signature = signer.sign(hash)
                # verifier.verify(msg_hash, msg_signature)
                return redirect(url_for('verify'))
            except Exception as e:
                return render_template('email_verify.html', form=form, error=e)
        else:
            return render_template('email_verify.html', form=form, error="Session Expired")
    return render_template('email_verify.html', form=form)


@app.route("/", methods=['GET', 'POST'])
def home():
    return redirect(url_for('email'))

@app.route("/results", methods=['GET'])
def results():
    try:
        resp = requests.get(backend_addr+'results')
        if(resp.status_code!=200):
            return render_template('confirmation.html',message=resp.text),resp.status_code
        result = eval(resp.text)
        print(result)
        result.sort(reverse=True,key=lambda x: x[2])
        return render_template('results.html',result=result)
    except:
        return render_template('confirmation.html',message="Error processing"),500
    
@app.route("/verify", methods=['GET', 'POST'])
def verify():
    try:
        resp = requests.get(backend_addr+'isended')
        print(resp)
        if(not eval(resp.text)):
            if request.method == 'POST':
                aid = request.form['aid']
                bio = request.form['biometric']
                resp = requests.get(backend_addr+'number_of_users')
                number_of_accounts = int(resp.text)
                if(bio == 'yes' and aid.isdigit() and int(aid)<=number_of_accounts):
                    session['verified'] = True
                    session['aid'] = int(aid)
                    return redirect(url_for('vote'))
            return render_template('verification.html')
        else:
            return render_template('confirmation.html',message="Election ended",code=400),400
    except:
        return render_template('confirmation.html',message="Error processing"),500

@app.route("/vote", methods=['GET', 'POST'])
def vote():
        resp = requests.get(backend_addr+'isended')
        if(not eval(resp.text)):
            if('verified' in session):
                resp = requests.get(backend_addr+'candidates_list')
                print(resp)
                candidates = eval(resp.text)
                print(candidates)
                candidates1 = candidates[:int(len(candidates)/2)]
                candidates2 = candidates[int(len(candidates)/2):]
                if request.method == 'POST':
                    aid = session['aid']
                    session.pop('verified')
                    session.pop('aid')
                    candidate = request.form['candidate']
                    cid = candidates.index(candidate)+1
                    print(cid)
                    resp = requests.post(backend_addr,json.dumps({'aadhaarID':aid,'candidateID':cid}))
                    print(resp)
                    return render_template('confirmation.html',message=resp.text,code=resp.status_code),resp.status_code
                return render_template('vote.html',candidates1=candidates1,candidates2=candidates2),200
            else:
                return redirect(url_for('home'))
        else:
            return render_template('confirmation.html',message="Election ended",code=400),400
    
if __name__ == '__main__':
	app.run(host="0.0.0.0" ,port=8000, debug = True)
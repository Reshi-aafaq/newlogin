import os
from flask_login import LoginManager,login_required
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import TextField ,PasswordField , SubmitField,ValidationError ,BooleanField
from wtforms.validators import  DataRequired ,EqualTo, Length ,Email
from flask import Flask , url_for, render_template , redirect,flash
from flask_bcrypt import Bcrypt
from flask_login import login_user ,current_user ,logout_user
from itsdangerous import TimedJSONWebSignatureSerializer as serializer
from flask_mail import Mail,Message
from email_validator import EmailNotValidError
app=Flask(__name__,template_folder='templates')
app.config['SECRET_KEY'] = "12sd34fgt1scv"
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://ufsxcdmmdwfszq:050b369945ccbfe16b68e01a05d064890239fb67550ee4ad1acac230e4bb37be@ec2-34-230-115-172.compute-1.amazonaws.com:5432/ddrvnct4dvtmel'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 
app.config['MAIL_PASSWORD'] = 
print(os.environ.get('EMAIL'))
mil =Mail(app)
db = SQLAlchemy(app)
bb = Bcrypt(app)
loginmanager = LoginManager(app)

@loginmanager.user_loader
def load_user(user_id):
    User.query.get(int(user_id))
class User(db.Model,UserMixin):
   
    id = db.Column(db.Integer , primary_key = True)
    username = db.Column(db.String(20),nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(60),nullable = False)

    def get_reset_token(self, expires_sec=1800):
        s = serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        se = serializer(app.config['SECRET_KEY'])
        try:
            user_id = se.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return f"user('{self.username}','{self.email}','{self.password}') "








class registerform(FlaskForm):
    user_name = TextField("Username:",validators=[DataRequired(),Length(min=3,max=20)])
    email = TextField("Email:",validators=[DataRequired() ,Email() ])
    password = PasswordField("Password:",validators=[DataRequired(),Length(min=5,max=10)])
    confirm = PasswordField("Confirm Password:",validators=[DataRequired(),EqualTo('password')])
    submit = SubmitField('Register')


    def validate_email(self,email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError(f'That email is already taken')


class Login(FlaskForm):

    email = TextField("Email:", validators=[DataRequired(), Email()])
    password = PasswordField("Password:", validators=[DataRequired(), Length(min=5, max=10)])
    submit = SubmitField('Login:')
    remember = BooleanField('Remember me')

class reset_password(FlaskForm):
    password = PasswordField("Password:",validators=[DataRequired(),Length(min=5,max=10)])
    confirm = PasswordField("Confirm Password:",validators=[DataRequired(),EqualTo('password')])
    submit = SubmitField('Update')

class reset_form(FlaskForm):
    email = TextField("Email:", validators=[DataRequired(), Email()])
    submit = SubmitField('Reset')

    def validate_email(self,email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError(f'Account doesnot exist')

class authoform(FlaskForm):
    Access = TextField("Access Password:", validators=[DataRequired()])
    submit = SubmitField('Show')

@app.route('/home11894ejbfiuegfrsdher%iuf%jfg#32oc')
def hoo():


    return render_template('hom.html')



@app.route('/',methods=['GET', 'POST'])
def index():
    if current_user.is_authenticated:
        return redirect(url_for('hoo'))
    formm = registerform()
    if formm.validate_on_submit():
        hashed_pass = bb.generate_password_hash(formm.password.data).decode('utf-8')
        user = User(username = formm.user_name.data , email = formm.email.data ,password= hashed_pass)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('signin'))

    return render_template('reg.html',form=formm)
@app.route('/login',methods=['GET', 'POST'])
def signin():
    if current_user.is_authenticated:
        return redirect(url_for('hoo'))
    form1 = Login()

    if form1.validate_on_submit():

        user = User.query.filter_by(email = form1.email.data).first()
        if user and bb.check_password_hash(user.password ,form1.password.data):
            login_user(user ,remember= form1.remember.data)
            return redirect(url_for('hoo'))
        else:
            flash('Data not found')

    return render_template('login.html' , form= form1)
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


def send_mail(user):
    token = user.get_reset_token()
    msg = Message('password request link' , sender= "noreply@me.com",recipients=[user.email])
    msg.body = f''' Click the link to reset the password: 
{url_for('newpass',token=token , _external=True)}
'''
    mil.send(msg)

@app.route('/resetdetail',methods =['GET','POST'])
def entermail():
    if current_user.is_authenticated:
        return redirect(url_for('hoo'))
    eform = reset_form()

    if eform.validate_on_submit():
        user = User.query.filter_by(email = eform.email.data).first()
        send_mail(user)

        return redirect(url_for('signin'))
    

    return render_template('emailre.html',form = eform)



@app.route('/resetpassword/<token>',methods=['GET','POST'])
def newpass(token):
    if current_user.is_authenticated:
        return redirect(url_for('hoo'))
    user = User.verify_reset_token(token)
    if user is None:
        return redirect(url_for('entermail'))

    pform = reset_password()
    if pform.validate_on_submit():
        hashed_pass = bb.generate_password_hash(pform.password.data).decode('utf-8')
        user.password = hashed_pass
        db.session.commit()
        return redirect(url_for('signin'))

    return render_template('resetpass.html',form = pform)

@app.route('/Ahiufh%jkvkjhfe',methods=['GET','POST'])
def goo():
    users = User.query.all()
    return render_template('authodata.html',infoo = users)
@app.route('/AccessDenied')
def accessdeny():
    return render_template('accessDenied.html')

@app.route('/show',methods = ['POST','GET'])

def database():
    myform = authoform()
    if myform.validate_on_submit():
        if myform.Access.data ==:
            return redirect(url_for('goo'))
        else:
            return redirect(url_for('accessdeny'))

    return render_template('autho.html',form = myform)




if __name__ == "__main__":
    app.run(debug=False)



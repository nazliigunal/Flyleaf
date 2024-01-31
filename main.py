from flask import Flask, render_template, request, redirect, url_for, flash, session, logging
from flask_login import LoginManager
from wtforms import Form, StringField, TextAreaField, PasswordField, validators 
from passlib.hash import sha256_crypt
from flask_mysqldb import MySQL
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from flask_mail import Mail, Message
from flask_login import UserMixin, login_user
from functools import wraps
from wtforms.validators import Email
from flask_login import current_user



app = Flask(__name__)
app.secret_key = "n_g_key_123321"


app.config["MYSQL_HOST"]="localhost"
app.config["MYSQL_USER"]="root"
app.config["MYSQL_PASSWORD"]=""
app.config["MYSQL_DB"]="okader"
app.config["SQLALCHEMY_DATABASE_URI"] = 'mysql://root:@localhost/okader'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MYSQL_CURSORCLASS"] = "DictCursor" 
engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
mysql=MySQL(app)
db = SQLAlchemy(app)


login_manager = LoginManager(app)
login_manager.login_view = 'girisyap'


# Kullanici Modeli
class Kullanici(db.Model, UserMixin):
    __tablename__ = 'Kullanici'
    id = db.Column(db.Integer, primary_key=True)
    kullanici_adi = db.Column(db.String(50), unique=True, nullable=False)
    sifre = db.Column(db.String(255), nullable=False)
    mail=db. Column(db.String(100), unique=True, nullable=False)
    ad = db.Column(db.String(50))
    soyad = db.Column(db.String(50))
    biyografi = db.Column(db.Text)
    profil_fotografi = db.Column(db.String(255))
    kapak_fotografi = db.Column(db.String(255))
    olusturma_tarihi = db.Column(db.DateTime, default=db.func.current_timestamp())
    yazilar = db.relationship('Yazi', back_populates='yazan')
        # Favori kitaplar
    favori_kitaplar = db.relationship('Kitap', secondary='favori_kitaplar', back_populates='favori_kullanicilar')

    # Okuyacakları kitaplar
    okuyacak_kitaplar = db.relationship('Kitap', secondary='okuyacak_kitaplar', back_populates='okuyacak_kullanicilar')

    yorumlar = db.relationship('Yorum', back_populates='yazan', lazy=True)


# Ortak tablo: favori_kitaplar
favori_kitaplar = db.Table('favori_kitaplar',
    db.Column('kullanici_id', db.Integer, db.ForeignKey('Kullanici.id')),
    db.Column('kitap_id', db.Integer, db.ForeignKey('Kitap.id'))
)

# Ortak tablo: okuyacak_kitaplar
okuyacak_kitaplar = db.Table('okuyacak_kitaplar',
    db.Column('kullanici_id', db.Integer, db.ForeignKey('Kullanici.id')),
    db.Column('kitap_id', db.Integer, db.ForeignKey('Kitap.id'))
)    

class Kitap(db.Model):
    __tablename__ = 'Kitap'
    id = db.Column(db.Integer, primary_key=True)
    ad = db.Column(db.String(100), unique=True , nullable=False)
    yazar = db.Column(db.String(100), nullable=False)
    tarih = db.Column(db.String(20))
    tur = db.Column(db.String(50))
    resim_yolu = db.Column(db.String(255))
    sayfa_sayisi = db.Column(db.String(50))
    ISBN = db.Column(db.String(50))
    konu = db.Column(db.String(50))
    çevirmen = db.Column(db.String(50))
    orijinal_ad = db.Column(db.String(50))
    favori_kullanicilar = db.relationship('Kullanici', secondary='favori_kitaplar', back_populates='favori_kitaplar')
    okuyacak_kullanicilar = db.relationship('Kullanici', secondary='okuyacak_kitaplar', back_populates='okuyacak_kitaplar')  
    okunan_kisi_sayisi = db.Column(db.Integer, default=0)
    favorilendi_sayisi = db.Column(db.Integer, default=0)  
    

class Yazi(db.Model):
    __tablename__ = 'Yazi'
    id = db.Column(db.Integer, primary_key=True)
    icerik = db.Column(db.Text, nullable=False)
    yazan_id = db.Column(db.Integer, db.ForeignKey('Kullanici.id'), nullable=False)
    yazilma_tarihi = db.Column(db.DateTime, default=datetime.utcnow)
    yazan = db.relationship('Kullanici', back_populates='yazilar')
    yorum_sayi= db.Column(db.Integer , default=0)
    yorumlar = db.relationship('Yorum', backref='yazi', lazy=True)

class Yorum(db.Model):
    __tablename__ = 'Yorum'
    id = db.Column(db.Integer, primary_key=True)
    icerik = db.Column(db.Text, nullable=False)
    yazan_id = db.Column(db.Integer, db.ForeignKey('Kullanici.id'), nullable=False)
    yazilma_tarihi = db.Column(db.DateTime, default=datetime.utcnow)
    yazi_id = db.Column(db.Integer, db.ForeignKey('Yazi.id'), nullable=False)
    yazan = db.relationship('Kullanici', back_populates='yorumlar')
    
    


# Kayıt Formu
class KaydolForm(Form):
    ad = StringField("Ad", [validators.DataRequired(), validators.Length(min=4, max=25)])
    soyad = StringField("Soyad", [validators.DataRequired(), validators.Length(min=4, max=25)])
    kullaniciadi = StringField("Kullanıcı Adı", [validators.DataRequired(), validators.Length(min=4, max=25)])
    mail = StringField("Mail", [validators.Email(), validators.Length(min=6, max=35)])
    sifre = PasswordField("Şifre Oluştur", [
        validators.DataRequired(),
        validators.EqualTo('sifretekrar', message='Şifreler eşleşmiyor')
    ])
    sifretekrar = PasswordField('Şifeyi Tekrar Gir')

# Giriş Formu
class GirisForm(Form):
    kullanici_adi = StringField("Kullanıcı Adı", [validators.DataRequired(), validators.Length(min=4, max=25)])
    sifre_ = PasswordField("Şifrenizi Girin", [validators.DataRequired()])

# Paylaşım formu
class PaylasForm(Form):
    post = TextAreaField("", [validators.DataRequired(), validators.Length(min=4, max=350)])

# Yorum formu
class YorumForm(Form):
    yorum = StringField("", [validators.DataRequired(), validators.Length(min=4, max=100)])

# Kullaniciyı kimlik doğrulama işlevi

@login_manager.user_loader
def load_user(user_id):
    return Kullanici.query.get(int(user_id))

@app.route('/login/<int:user_id>')
def login(user_id):
    user = Kullanici.query.get(user_id)
    login_user(user)
    return redirect(url_for("profil", username=session["username"]))


# Websiteye girince açılan ilk sayfa 
# Giriş Yap sayfası
# Giriş Yap sayfası
@app.route('/', methods=["GET","POST"])
def girisyap():
    form = GirisForm(request.form)
    if request.method == "POST":
        kullaniciAdi=form.kullanici_adi.data
        sifre=form.sifre_.data
        kullanici = Kullanici.query.filter_by(kullanici_adi=kullaniciAdi).first()
        if kullanici :
            if sha256_crypt.verify(sifre, kullanici.sifre):
                session["logged_in"] = True
                session["username"] = kullaniciAdi

                session["user_id"]=kullanici.id
                return login(kullanici.id)
            else:
                flash("Şifrenizi Yanlış Girdiniz!!","danger")
                return redirect(url_for("girisyap"))
            
        else:
            flash("Böyle Bir Kullanıcı Bulunmuyor!!","danger")
            return redirect(url_for("girisyap"))

    return render_template("giris.html", form=form)

# Kayıt olma sayfasını oluşturma
@app.route('/kaydol', methods=["GET", "POST"])
def kaydol():
    form = KaydolForm(request.form)
    if request.method == "POST" and form.validate():
        kullaniciAdiForm=form.kullaniciadi.data
        kullanici = Kullanici.query.filter_by(kullanici_adi=kullaniciAdiForm).first()
        if kullanici is None:
             yeni_kullanici=Kullanici(kullanici_adi=form.kullaniciadi.data,
                                 sifre=sha256_crypt.hash(form.sifre.data),
                                 mail=form.mail.data,
                                 ad=form.ad.data,
                                 soyad=form.soyad.data,
                                 )
             db.session.add(yeni_kullanici)
             yeni_kullanici.olusturma_tarihi = datetime.utcnow()
             db.session.commit()
             flash("Kayıt Başarılı Şekilde Gerçekleşti","success")
             return redirect(url_for("girisyap"))
        else:
            flash("Böyle Bir Kullanıcı Var","danger")
            return redirect(url_for("kaydol"))    
    else:
        flash("Geçerli bir e-posta adresi giriniz.", "danger")    
    return render_template("kaydol.html", form=form)



#decoratorler kullanılarak sayfalara giriş yapmadan ulaşmayı engellemek
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" in session:
             return f(*args, **kwargs)
        else:
            return redirect(url_for("girisyap"))

    return decorated_function



# Kütüphane sayfası
@app.route('/kutuphane', methods=["GET", "POST"])
@login_required
def kutuphane():
    kitaplar = Kitap.query.all()
    kullanici=session["username"]
    return render_template("kutuphane.html", kitaplar = kitaplar,kullanici=kullanici)

# Ana sayfa
@app.route('/anasayfa', methods=["GET", "POST"])
@login_required
def anasayfa():
    yazilar = Yazi.query.all()
    
    return render_template("anasayfa.html",yazilar=yazilar)


# Profil sayfası
@app.route('/profil/<username>', methods=["GET", "POST"])
@login_required
def profil(username):
    kullanici = Kullanici.query.filter_by(kullanici_adi=username).first()
    if kullanici:
        if 'okuma_ekle' in request.form:
            return redirect(url_for('yorum'))
        
        form = PaylasForm(request.form)
        if request.method == 'POST':
            if form.validate():
                yeni_yazi = Yazi(icerik=form.post.data, yazan_id=kullanici.id)
                db.session.add(yeni_yazi)
                yeni_yazi.yazilma_tarihi = datetime.utcnow()
                db.session.commit()
                flash("Yazı başarıyla paylaşıldı.", "success")
                return redirect(url_for('anasayfa'))
            else:
                flash("Formu doğru bir şekilde doldurunuz.", "danger")
        kullanici_yazilari = Yazi.query.filter_by(yazan_id=kullanici.id).all()        
        return render_template('profil.html',form=form, kullanici=kullanici, kullanici_yazilari=kullanici_yazilari)
    else:
        flash("Kullanıcı Bulunamadı", "danger")
        return redirect(url_for("girisyap"))
    
@app.route('/ekle', methods=['POST'])
@login_required
def ekle():
    if request.method == 'POST':
            kitap_id = request.form.get('kitap_id')

        
            kullanici_id = current_user.id
        
            # Formdan gelen butonun ismini kontrol et
            if 'okuma_ekle' in request.form:
              # Kullanıcının okuma listesine ekleme işlemleri burada gerçekleştirilir
               kullanici = Kullanici.query.get(kullanici_id)
               kitap = Kitap.query.get(kitap_id)
               if kitap not in kullanici.okuyacak_kitaplar:
                    if kitap not in kullanici.favori_kitaplar:
                         kullanici.okuyacak_kitaplar.append(kitap)
                         flash("Kitap başarıyla okuma listene eklendi.", "success")
                    else:
                           flash("Bu kitabı okumuşsunuz.", "danger")   
               else:
                     flash("Bu kitap okuma listende zaten var.", "danger")  
            elif 'okuduklari_ekle' in request.form:
            # Kullanıcının okuduklarına ekleme işlemleri burada gerçekleştirilir
               kullanici = Kullanici.query.get(kullanici_id)
               kitap = Kitap.query.get(kitap_id)

               if kitap not in kullanici.favori_kitaplar:
                    
                    if kitap in kullanici.okuyacak_kitaplar:
                        kullanici.okuyacak_kitaplar.remove(kitap)

                    kullanici.favori_kitaplar.append(kitap)
                    flash("Kitap başarıyla okuduklarına eklendi ve okuma listenden kaldırıldı.", "success")
               else:
                   flash("Bu kitap okuduklarında zaten var.", "danger") 
            db.session.commit()

    return redirect(url_for('kutuphane')) 
# Okuma Listem
@app.route('/okumaListem', methods=["GET", "POST"])
@login_required
def okumaListem():
    kullanici_id = current_user.id
    kullanici = Kullanici.query.get(kullanici_id)
    return render_template("okucaklarim.html",kullanici=kullanici) 
  
# Okuduklarım
@app.route('/okuduklarim', methods=["GET", "POST"])
@login_required
def okuduklarim():
    kullanici_id = current_user.id
    kullanici = Kullanici.query.get(kullanici_id)
    return render_template("okuduklarim.html",kullanici=kullanici)  


#yorum kodları
@app.route('/yorum', methods=["GET", "POST"])
@login_required
def yorum():
    
    yazi_id = request.form.get("yazi")
    yazi = Yazi.query.get(yazi_id)

    kullanici_id=request.form.get("kullanici")
    yazi_kullanici = Kullanici.query.get(kullanici_id)
    form = YorumForm(request.form)

    if request.method == 'POST' and form.validate():
        icerik = form.yorum.data
        if not icerik:
            flash("Yorum içeriği boş olamaz.", "danger")
        else:
            yeni_yorum = Yorum(icerik=icerik,yazi_id=yazi.id, yazan_id=current_user.id )
            db.session.add(yeni_yorum)
            yeni_yorum.olusturma_tarihi = datetime.utcnow()
            db.session.commit()

            flash("Yorum başarıyla eklendi.", "success")
   
    yazi = Yazi.query.get(yazi_id)

    return render_template("yorum.html", yazi=yazi, form=form , yazi_kullanici=yazi_kullanici,kullanici=current_user)


#Çıkış yapma işlemi
@app.route("/cikis.yap")
def cikis():
    session.clear()
    flash("Çıkış Başarıyla Gerçekleşti","success")
    return redirect(url_for("girisyap"))



if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)  

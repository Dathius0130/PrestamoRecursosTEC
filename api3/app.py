from flask import Flask, jsonify, request
from conexion.db import db
from flask_cors import CORS
from flask_cors import CORS, cross_origin
from routes.perfilr import perfil
from routes.estador import estado
from routes.itemr import item
from routes.usuarior import usuario
from routes.inventarior import inventario
from routes.solicitudr import solicitud
from routes.prestamor import prestamo

app = Flask(__name__)
cors = CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://h6mj0ki7lg34eylplyjk:pscale_pw_sbuCxVruMhAJKvIwYPC8QET0e1szsX2LbU1hwRtQxPi@aws.connect.psdb.cloud/prestamo?ssl={"rejectUnauthorized":true}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
app.register_blueprint(perfil)
app.register_blueprint(estado)
app.register_blueprint(item)
app.register_blueprint(usuario)
app.register_blueprint(inventario)
app.register_blueprint(solicitud)
app.register_blueprint(prestamo)

@app.route('/')
@cross_origin() 
def index():
    return jsonify({'message': 'welcome'})

def pagina_no_encontrada(error):
    return "<h1>La pagina a la que intentas acceder no existe...</h1>"

if __name__=="__main__":
    app.register_error_handler(404 , pagina_no_encontrada)
    app.run(debug=True)

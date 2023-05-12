from enum import unique
from conexion.db import db

class Usuario(db.Model):
    __tablename__ = 'usuario'
    userId = db.Column(db.Integer, primary_key=True)
    usuario = db.Column(db.String(50), nullable=False,unique=True)
    nombre = db.Column(db.String(50), nullable=False)
    apellido = db.Column(db.String(50), nullable=False)
    identificacion = db.Column(db.Integer, nullable=False,unique=True)
    correo = db.Column(db.String(50), nullable=False,unique=True)
    perfilId = db.Column(db.Integer, db.ForeignKey('perfil.perfilId'), nullable=False)
    password = db.Column(db.String(50), nullable=False)



    def __init__(self, userId, usuario, nombre, apellido, identificacion,correo,perfilId,password):
        self.userId = userId
        self.usuario = usuario
        self.nombre = nombre
        self.apellido = apellido
        self.identificacion = identificacion
        self.correo = correo
        self.perfilId = perfilId
        self.password = password

    def getDatos(self):
        return {
           "userId" :  self.userId,
           "Usuario" : self.usuario,
           "Nombre" : self.nombre,
           "Apellido" : self.apellido,
           "Identificacion" : self.identificacion,
           "Correo" : self.correo,
           "Perfil" : self.perfilId, 
           "password" : self.password
        }
from enum import unique
from conexion.db import db

class Perfil(db.Model):
    __tablename__ = 'perfil'
    perfilId = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(500), nullable=False,unique=True)
    descripcion = db.Column(db.String(50), nullable=False)
   

    def __init__(self, perfilId, nombre, descripcion):
        self.perfilId = perfilId
        self.nombre = nombre
        self.descripcion = descripcion
        

    def getDatos(self):
        return {
            'perfilid': self.perfilId,
            'perfil': self.nombre,
            'descripcion': self.descripcion
        }
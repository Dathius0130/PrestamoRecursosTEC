from enum import unique
from conexion.db import db

class Estado(db.Model):
    __tablename__ = 'estado'
    estadoId = db.Column(db.Integer, primary_key=True)
    estado = db.Column(db.String(50), nullable=False,unique=True)


    def __init__(self, estadoId, estado):
        self.estadoId = estadoId
        self.estado = estado
            

    def getDatos(self):
        return {
            'Id del estado': self.estadoId,
            'Estado': self.estado
        }
from enum import unique
from conexion.db import db

class Item(db.Model):
    __tablename__ = 'item'
    itemId = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50))
    descripcion = db.Column(db.String(50))
    tipo = db.Column(db.String(50))

    def __init__(self, itemId, nombre, descripcion, tipo):
        self.itemId = itemId
        self.nombre = nombre
        self.descripcion = descripcion
        self.tipo = tipo

            

    def getDatos(self):
        return {
            'itemid': self.itemId,
            'item': self.nombre,
            'descripcion':self.descripcion,
            'tipo':self.tipo
        }
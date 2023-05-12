from enum import unique
from conexion.db import db

class Inventario(db.Model):
    __tablename__ = 'inventario'
    inventarioId = db.Column(db.Integer, primary_key=True)
    cantidad = db.Column(db.Integer, nullable=False,)
    itemId = db.Column(db.Integer, db.ForeignKey('item.itemId'), nullable=False,unique=True)
   

    def __init__(self, inventarioId, cantidad, itemId):
        self.inventarioId = inventarioId
        self.cantidad = cantidad
        self.itemId = itemId
        

    def getDatos(self):
        return {
            'inventarioid': self.inventarioId,
            'cantidad': self.cantidad,
            'item': self.itemId
        }
from enum import unique
from conexion.db import db

class Solicitud(db.Model):
    __tablename__ = 'solicitud'
    solicitudId = db.Column(db.Integer, primary_key=True)
    userId = db.Column(db.Integer, db.ForeignKey('usuario.userId'), nullable=False)
    itemId = db.Column(db.Integer, db.ForeignKey('item.itemId'), nullable=False)
    fechaSolicitud = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp(), nullable=False)
    estadoId = db.Column(db.Integer, db.ForeignKey('estado.estadoId'), nullable=False)
    observacion = db.Column(db.String(500))

    def __init__(self, userId, itemId, estadoId, observacion=None):
        self.userId = userId
        self.itemId = itemId
        self.estadoId = estadoId
        self.observacion = observacion

    def getDatos(self):
        return {
            "solicitud": self.solicitudId,
            "usuario": self.userId,
            "item": self.itemId,
            "fechasolicitud": self.fechaSolicitud,
            "estado": self.estadoId,
            "observacion": self.observacion
        }

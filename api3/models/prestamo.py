from enum import unique
from conexion.db import db

class Prestamo(db.Model):
    __tablename__ = 'prestamo'
    prestamoId = db.Column(db.Integer, primary_key=True)
    solicitudId = db.Column(db.Integer, db.ForeignKey('solicitud.solicitudId'), unique=True, nullable=False)
    fechaPrestamo = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp(), nullable=False)
    fechaDevolucion = db.Column(db.DateTime)
    observacion = db.Column(db.String(500))

    def __init__(self, prestamoId, solicitudId, fechaPrestamo, fechaDevolucion=None, observacion=None):
        self.prestamoId = prestamoId
        self.solicitudId = solicitudId
        self.fechaPrestamo = fechaPrestamo
        self.fechaDevolucion = fechaDevolucion
        self.observacion = observacion

    def getDatos(self):
        return {
            "prestamoid": self.prestamoId,
            "solicitudid": self.solicitudId,
            "fechaprestamo": self.fechaPrestamo,
            "fechadevolucion": self.fechaDevolucion,
            "observacion": self.observacion
        }

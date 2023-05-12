from flask import jsonify, request
from models.prestamo import *

class Prestamoc:

    def consultar_prestamos(self):
        if request.method == 'GET':
            prestamos = Prestamo.query.all()
            if not prestamos:
                return jsonify({'message': 'no hay prestamos'})
            else:
                toPrestamos = [prestamo.getDatos() for prestamo in prestamos]
                return jsonify(toPrestamos)


    def insertar_prestamo(self):
        fechaPrestamo = request.json["fechaPrestamo"]
        fechaDevolucion = request.json["fechaDevolucion"]
        observacion = request.json["observacion"]
        new_prestamo = Prestamo(None, fechaPrestamo, fechaDevolucion, observacion)
        db.session.add(new_prestamo)
        db.session.commit()
        return jsonify({
                'message':'Prestamo registrado con exito',
                'status':'ok'
                }) 
    
    def consultar_prestamo(self):
        prestamoId = request.json["prestamoId"]
        c_prestamo = Prestamo.query.get(prestamoId)
        if not c_prestamo:
            return jsonify({'message': 'Prestamo not found'})
        else:
            return jsonify(c_prestamo.getDatos())

    def editar_prestamo(self):
        prestamoId = request.json["prestamoId"]
        c_prestamo = Prestamo.query.get(prestamoId)
        if not c_prestamo:
            return jsonify({'message': 'Prestamo no encontrado'})
        else:
            c_prestamo.solicitudId = request.json["solicitudId"]
            c_prestamo.fechaPrestamo = request.json["fechaPrestamo"]
            c_prestamo.fechaDevolucion = request.json["fechaDevolucion"]
            c_prestamo.observacion = request.json["observacion"]
            db.session.commit()
            return jsonify({'message': 'Prestamo actualizado con exito'})


    def eliminar_prestamo(self):
        prestamoId = request.json["prestamoId"]
        c_prestamo = Prestamo.query.get(prestamoId)
        if not c_prestamo:
            return jsonify({'message': 'Prestamo no encontrado'})
        else:
            db.session.delete(c_prestamo)
            db.session.commit()
            return jsonify({'message': 'Prestamo eliminado con exito'})

from flask import jsonify, request
from models.estado import *

class Estadoc():

    def consultar_estados(self):
        if request.method == 'GET':
            Estados = Estado.query.all()
            if not Estados:
                return jsonify({'message': 'no hay estados'})
            else:
                toEstados = [Estado.getDatos() for Estado in Estados]
                return jsonify(toEstados)

    def insertar_estado(self):
        
        estado = request.json["estado"]
        new_estado = Estado(estado)
        db.session.add(new_estado)
        db.session.commit()
        return jsonify({
                'message':'Estado registrado con exito',
                'status':'ok'
                })
    
    def consultar_estado_nombre(self):

        estado = request.json["estado"]
        c_estado = Estado.query.filter_by(estado).first()
        if not c_estado:
            return jsonify({'message': 'Estado not found'})
        else:
            return jsonify(c_estado.getDatos())    
    
    def consultar_estado(self):

        estadoId = request.json["estadoId"]
        c_estado = Estado.query.get(estadoId)
        if not c_estado:
            return jsonify({'message': 'Estado not found'})
        else:
            return jsonify(c_estado.getDatos())

    def editar_Estado(self):
        estadoId = request.json["estadoId"]
        c_estado = Estado.query.get(estadoId)
        if not c_estado:
            return jsonify({'message': 'Estado no encontrado'})
        else:
            c_estado.estado = request.json["estado"]
            db.session.commit()
            return jsonify({'message': 'Estado actualizado con exito'})


    def eliminar_estado(self):
        estadoId = request.json["estadoId"]
        c_estado = Estado.query.get(c_estado)
        if not c_estado:
            return jsonify({'message': 'Estado no encontrado'})
        else:
            db.session.delete(c_estado)
            db.session.commit()
            return jsonify({'message': 'Estado eliminado con exito'})
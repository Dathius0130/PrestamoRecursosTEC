from flask import jsonify, request
from models.solicitud import *
from models.usuario import *
from models.item import *
from models.estado import *

class Solicitudc:

    def consultar_solicitudes2(self):
        if request.method == 'GET':
            solicitudes = Solicitud.query.all()
            if not solicitudes:
                return jsonify({'message': 'no hay solicitudes'})
            else:
                toSolicitudes = [solicitud.getDatos() for solicitud in solicitudes]
                return jsonify(toSolicitudes)

    def consultar_solicitudes(self):
        if request.method == 'GET':
            solicitudes = db.session.query(Solicitud.solicitudId,Usuario.usuario.label('usuario'),Item.nombre.label('item'), Solicitud.fechaSolicitud, Estado.estado.label('estado'),Solicitud.observacion
                                        ).join(Usuario, Solicitud.userId == Usuario.userId).join(Item, Solicitud.itemId == Item.itemId).join(Estado, Solicitud.estadoId == Estado.estadoId).all()
            if not solicitudes:
                return jsonify({'message': 'No hay solicitud'})
            else:
                toSolicitud = []
                for solicitud in solicitudes:
                    solicitudDict = {}
                    solicitudDict['solicitud'] = solicitud[0]
                    solicitudDict['usuario'] = solicitud[1]
                    solicitudDict['item'] = solicitud[2]
                    solicitudDict['fecha'] = solicitud[3]
                    solicitudDict['estado'] = solicitud[4]
                    solicitudDict['observacion'] = solicitud[5]
                    toSolicitud.append(solicitudDict)
                return jsonify(toSolicitud)
            
    def insertar_solicitud(self):
        userId = request.json["userId"]
        itemId = request.json["itemId"]
        new_solicitud = Solicitud(userId, itemId,estadoId=1)
        db.session.add(new_solicitud)
        db.session.commit()
        return jsonify({
                'message':'Solicitud registrada con exito',
                'status':'ok'
                }) 
    
    def consultar_solicitud(self, id):
         c_solicitud = db.session.query(Solicitud.solicitudId,Usuario.usuario.label('usuario'),Item.nombre.label('item'), Solicitud.fechaSolicitud, Estado.estado.label('estado'),Solicitud.observacion
                                        ).filter_by(userId=id).join(Usuario, Solicitud.userId == Usuario.userId).join(Item, Solicitud.itemId == Item.itemId).join(Estado, Solicitud.estadoId == Estado.estadoId).all()
         if not c_solicitud:
             return jsonify({'message': 'Solicitud not found'})
         else:
             toSolicitud = []
             for solicitud in c_solicitud:
                    solicitudDict = {}
                    solicitudDict['solicitudId'] = solicitud[0]
                    solicitudDict['usuario'] = solicitud[1]
                    solicitudDict['item'] = solicitud[2]
                    solicitudDict['fecha'] = solicitud[3]
                    solicitudDict['estado'] = solicitud[4]
                    solicitudDict['observacion'] = solicitud[5]
                    toSolicitud.append(solicitudDict)
             return jsonify(toSolicitud)

        
    def consultar_solicitud_user(self):
        userId = request.args.get("userId")
        c_solicitud = Solicitud.query.filter_by(id=userId).first()
        if not c_solicitud:
            return jsonify({'message': 'Solicitud not found'})
        else:
            return jsonify(c_solicitud.getDatos())


    def editar_solicitud(self):
        solicitudId = request.json["solicitudId"]
        c_solicitud = Solicitud.query.get(solicitudId)
        if not c_solicitud:
            return jsonify({'message': 'Solicitud no encontrada'})
        else:
            c_solicitud.userId = request.json["userId"]
            c_solicitud.itemId = request.json["itemId"]
            c_solicitud.estadoId = request.json["estadoId"]
            c_solicitud.observacion = request.json["observacion"]
            db.session.commit()
            return jsonify({'message': 'Solicitud actualizada con exito'})


    def eliminar_solicitud(self):
        solicitudId = request.json["solicitudId"]
        c_solicitud = Solicitud.query.get(solicitudId)
        if not c_solicitud:
            return jsonify({'message': 'Solicitud no encontrada'})
        else:
            db.session.delete(c_solicitud)
            db.session.commit()
            return jsonify({'message': 'Solicitud eliminada con exito'})

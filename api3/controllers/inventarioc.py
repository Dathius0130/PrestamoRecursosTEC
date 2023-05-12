from sqlalchemy import func,case
from flask import jsonify, request
from models.inventario import *
from models.item import *
from models.solicitud import *
class Inventarioc():

    def ultima_fila(self):
        if request.method == 'GET':
         count = Inventario.query.count()
        if count == 0:
            return jsonify({'message': 'no hay Inventarios'})
        
        return jsonify({'count': count+1})

            
    def consultar_inventario(self):
        if request.method == 'GET':
            inventarios = db.session.query(
                Inventario.inventarioId,
                Inventario.cantidad,
                Item.nombre.label('item'),
                case((Solicitud.estadoId == 5, Inventario.cantidad - func.count(Solicitud.itemId)), else_=Inventario.cantidad).label('cantidad_disponible')
                ).join(
                Item,
                Inventario.itemId == Item.itemId
                ).outerjoin(
                Solicitud,
                Item.itemId == Solicitud.itemId
                ).group_by(
                Item.itemId,
                Solicitud.estadoId
                ).all()

        if not inventarios:
            return jsonify({'message': 'No hay inventario'})
        else:
            toInventario = []
            for inventario in inventarios:
                inventarioDict = {}
                inventarioDict['inventario'] = inventario[0]
                inventarioDict['cantidad'] = inventario[1]
                inventarioDict['item'] = inventario[2]
                inventarioDict['cantidad_disponible'] = inventario[3]
                toInventario.append(inventarioDict)
            return jsonify(toInventario)


    def insertar_inventario(self):
        cantidad = request.json["cantidad"]
        itemId = request.json["itemId"]
        new_invetario = Inventario(None,cantidad,itemId)
        db.session.add(new_invetario)
        db.session.commit()
        return jsonify({
                'message':'Inventario registrado con exito',
                'status':'ok'
                })
    
    def consultar_consultar_id(self):

        inventarioId = request.json["inventarioId"]
        c_Inventario = Inventario.query.get(inventarioId)
        if not c_Inventario:
            return jsonify({'message': 'Inventario not found'})
        else:
            return jsonify(c_Inventario.getDatos())

    def editar_inventario(self):
        inventarioId = request.json["inventarioId"]
        c_Inventario = Inventario.query.get(inventarioId)
        if not c_Inventario:
            return jsonify({'message': 'Inventario no encontrado'})
        else:
            c_Inventario.nombre = request.json["nombre"]
            c_Inventario.descripcion = request.json["descripcion"]
            db.session.commit()
            return jsonify({'message': 'Inventario actualizado con exito'})


    def eliminar_inventario(self):
        inventarioId = request.json["inventarioId"]
        c_Inventario = inventarioId.query.get(c_Inventario)
        if not c_Inventario:
            return jsonify({'message': 'Inventario no encontrado'})
        else:
            db.session.delete(c_Inventario)
            db.session.commit()
            return jsonify({'message': 'Inventario eliminado con exito'})
from flask import jsonify, request
from models.item import *

class Itemc():

    def consultar_items(self):
        if request.method == 'GET':
            Items = Item.query.all()
            if not Items:
                return jsonify({'message': 'no hay items'})
            else:
                toItems = [Item.getDatos() for Item in Items]
                return jsonify(toItems)

    def insertar_items(self):
        nombre = request.json["nombre"]
        descripcion = request.json["descripcion"]
        tipo = request.json["tipo"]
        new_items = Item(None,nombre,descripcion,tipo)
        db.session.add(new_items)
        db.session.commit()
        return jsonify({
                'message':'Item registrado con exito',
                'status':'ok'
                }) 
    
    def consultar_item(self):

        itemId = request.json["itemId"]
        c_item = Item.query.get(itemId)
        if not c_item:
            return jsonify({'message': 'Item not found'})
        else:
            return jsonify(c_item.getDatos())

    def editar_item(self):
        itemId = request.json["itemId"]
        c_item = Item.query.get(itemId)
        if not c_item:
            return jsonify({'message': 'Item no encontrado'})
        else:
            c_item.nombre = request.json["nombre"]
            c_item.descripcion = request.json["descripcion"]
            c_item.tipo = request.json["tipo"]
            db.session.commit()
            return jsonify({'message': 'Item actualizado con exito'})


    def eliminar_estado(self):
        itemId = request.json["itemId"]
        c_item = Item.query.get(c_item)
        if not c_item:
            return jsonify({'message': 'Item no encontrado'})
        else:
            db.session.delete(c_item)
            db.session.commit()
            return jsonify({'message': 'Item eliminado con exito'})
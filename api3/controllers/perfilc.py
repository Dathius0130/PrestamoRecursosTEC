from flask import jsonify, request
from models.perfil import *

class Perfilc():

    def consultar_perfiles(self):
        if request.method == 'GET':
            perfiles = Perfil.query.all()
            if not perfiles:
                return jsonify({'message': 'no hay perfiles'})
            else:
                toPerfiles = [Perfil.getDatos() for Perfil in perfiles]
                return jsonify(toPerfiles)

    def insertar_perfil(self):
        
        nombre = request.json["nombre"]
        descripcion = request.json["descripcion"]
        new_perfil = Perfil(nombre,descripcion)
        db.session.add(new_perfil)
        db.session.commit()
        return jsonify({
                'message':'Perfil registrado con exito',
                'status':'ok'
                })
    
    def consultar_perfil_id(self):

        perfilId = request.json["perfilId"]
        c_Perfil = Perfil.query.get(perfilId)
        if not c_Perfil:
            return jsonify({'message': 'Perfil not found'})
        else:
            return jsonify(c_Perfil.getDatos())

    def consultar_perfil_nombre(self):

        nombre = request.json["nombre"]
        c_Perfil = Perfil.query.filter_by(nombre).first()
        if not c_Perfil:
            return jsonify({'message': 'Perfil not found'})
        else:
            return jsonify(c_Perfil.getDatos())

    def editar_Perfil(self):
        perfilId = request.json["perfilId"]
        c_perfil = Perfil.query.get(perfilId)
        if not c_perfil:
            return jsonify({'message': 'Perfil no encontrado'})
        else:
            c_perfil.nombre = request.json["nombre"]
            c_perfil.descripcion = request.json["descripcion"]
            db.session.commit()
            return jsonify({'message': 'Perfil actualizado con exito'})


    def eliminar_perfil(self):
        perfilId = request.json["perfilId"]
        c_perfil = Perfil.query.get(perfilId)
        if not c_perfil:
            return jsonify({'message': 'Perfil no encontrado'})
        else:
            db.session.delete(c_perfil)
            db.session.commit()
            return jsonify({'message': 'Perfil eliminado con exito'})
from flask import jsonify, request, make_response
from models.usuario import *
from models.perfil import *
import jwt
from datetime import datetime, timedelta
import hashlib as h
key='asfubsdivg'


class Usuarioc():

    def consultar_usuarios(self):
        if request.method == 'GET':
            usuarios = db.session.query(Usuario.userId, Usuario.usuario, Usuario.nombre, Usuario.apellido, 
                                        Usuario.identificacion, Usuario.correo, Perfil.nombre.label('perfil'), 
                                        Usuario.password).join(Perfil, Usuario.perfilId == Perfil.perfilId).all()
            if not usuarios:
                return jsonify({'message': 'No hay usuarios'})
            else:
                toUsuarios = []
                for usuario in usuarios:
                    usuarioDict = {}
                    usuarioDict['userId'] = usuario[0]
                    usuarioDict['usuario'] = usuario[1]
                    usuarioDict['nombre'] = usuario[2]
                    usuarioDict['apellido'] = usuario[3]
                    usuarioDict['identificacion'] = usuario[4]
                    usuarioDict['correo'] = usuario[5]
                    usuarioDict['perfil'] = usuario[6]
                    usuarioDict['password'] = usuario[7]
                    toUsuarios.append(usuarioDict)
                return jsonify(toUsuarios)

    def insertar_usuario(self):
        usuario = request.json["usuario"]
        nombre = request.json["nombre"]
        apellido = request.json["apellido"]
        identificacion = request.json["identificacion"]
        correo = request.json["correo"]
        perfilId = request.json["perfilId"]
        password = request.json["password"]
        new_usuario = Usuario(None,usuario,nombre,apellido,identificacion,correo,perfilId,password)
        db.session.add(new_usuario)
        db.session.commit()
        return jsonify({
                'message':'Usuario registrado con exito',
                'status':'ok'
                }) 
    
    def consultar_usuario_pass(self):
        usuario = request.json['usuario']
        contra = request.json['password']
        password = h.sha256(contra.encode()).hexdigest()
        c_usuario = Usuario.query.filter_by(usuario=usuario).first()
        if c_usuario and c_usuario.password == password:
            payload = {
                'usuario': usuario,
                'perfil': c_usuario.perfilId,
                'exp':datetime.utcnow()+timedelta(hours=5,minutes=1)
            }
            token = jwt.encode(payload, key, algorithm='HS256')
            response = make_response(jsonify({
                                            "userId" :  c_usuario.userId,
                                            "Usuario" : c_usuario.usuario,
                                            "Nombre" : c_usuario.nombre,
                                            "Apellido" : c_usuario.apellido,
                                            "Identificacion" : c_usuario.identificacion,
                                            "Correo" : c_usuario.correo,
                                            "Perfil" : c_usuario.perfilId, 
                                            "password" : c_usuario.password,
                                            "token":token}))
            return response
        else:
            response = make_response(jsonify({'error': 'Credenciales incorrectas'}), 300)
            return response
    
    def validar_token(self):
        try:
            token = request.json['token']
            decoded_token = jwt.decode(token, key, algorithms=['HS256'])
            expiracion = datetime.fromtimestamp(decoded_token['exp'])
            if datetime.utcnow() < expiracion:
                return jsonify({'valid': True})
            else:
                return jsonify({'valid': False, 'error': 'Token expirado'}), 401
        except jwt.exceptions.ExpiredSignatureError:
            return jsonify({'valid': False, 'error': 'Token expirado'}), 401
        except jwt.exceptions.InvalidTokenError:
            return jsonify({'valid': False, 'error': 'Token inválido'}), 401
    def editar_usuario(self):
        userId = request.json["userId"]
        c_usuario = Usuario.query.get(userId)
        if not c_usuario:
            return jsonify({'message': 'Usuario no encontrado'})
        else:
            c_usuario.usuario = request.json["usuario"]
            c_usuario.nombre = request.json["nombre"]
            c_usuario.apellido = request.json["apellido"]
            c_usuario.identifiacion = request.json["identifiacion"]
            c_usuario.correo = request.json["correo"]
            c_usuario.perfilId = request.json["perfilId"]
            c_usuario.password = request.json["password"]
            db.session.commit()
            return jsonify({'message': 'Usuario actualizado con exito'})

    def eliminar_usuario(self):
        userId = request.json["userId"]
        c_usuario = Usuario.query.get(userId)
        if not c_usuario:
            return jsonify({'message': 'Usuario no encontrado'})
        else:
            db.session.delete(c_usuario)
            db.session.commit()
            return jsonify({'message': 'Usuario eliminado con exito'})
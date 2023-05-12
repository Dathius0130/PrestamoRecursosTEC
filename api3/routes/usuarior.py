from flask import Flask, jsonify, request, Blueprint
from flask_cors import  cross_origin
from controllers.usuarioc import *

usuario = Blueprint('usuario', __name__)

con_item = Usuarioc()

@usuario.route('/usuarios', methods=['GET'])
@cross_origin() 
def consultar_usuarios():
    return con_item.consultar_usuarios()

@usuario.route('/consultar/usuarios/id', methods=['GET'])
@cross_origin() 
def consultar_usuario():
    return con_item.consultar_usuario()

@usuario.route('/insertar/usuario', methods=['POST'])
@cross_origin() 
def insertar_usuario():
    return con_item.insertar_usuario()

@usuario.route('/editar/usuario', methods=['PUT'])
@cross_origin() 
def editar_usuario():
    return con_item.editar_usuario()

@usuario.route('/eliminar/usuario', methods=['DELETE'])
@cross_origin() 
def eliminar_usuario():
    return con_item.eliminar_usuario()

@usuario.route('/Login', methods=['POST'])
@cross_origin() 
def consultar_usuario_pass():
    return con_item.consultar_usuario_pass()

@usuario.route('/validar/token', methods=['POST'])
@cross_origin()
def validar_token():
    return con_item.validar_token()

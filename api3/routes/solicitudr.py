from flask import Flask, jsonify, request, Blueprint
from flask_cors import cross_origin
from controllers.solicitudc import *

solicitud = Blueprint('solicitud', __name__)

con_solicitud = Solicitudc()

@solicitud.route('/solicitudes', methods=['GET'])
@cross_origin() 
def consultar_solicitudes():
    return con_solicitud.consultar_solicitudes()

@solicitud.route('/consultar/solicitud/<id>', methods=['GET'])
@cross_origin() 
def consultar_solicitud(id):
    return con_solicitud.consultar_solicitud(id)

@solicitud.route('/insertar/solicitud', methods=['POST'])
@cross_origin() 
def insertar_solicitud():
    return con_solicitud.insertar_solicitud()

@solicitud.route('/editar/solicitud', methods=['PUT'])
@cross_origin() 
def editar_solicitud(solicitudId):
    return con_solicitud.editar_solicitud(solicitudId)

@solicitud.route('/eliminar/solicitud', methods=['DELETE'])
@cross_origin() 
def eliminar_solicitud(solicitudId):
    return con_solicitud.eliminar_solicitud(solicitudId)

from flask import Flask, jsonify, request, Blueprint
from flask_cors import cross_origin

from controllers.estadoc import *

estado = Blueprint('estado', __name__)

con_estado = Estadoc()

@estado.route('/estados', methods=['GET'])
@cross_origin() 
def consultar_estados():
    return con_estado.consultar_estados()

@estado.route('/consultar/estado/id', methods=['GET'])
@cross_origin() 
def consultar_estado():
    return con_estado.consultar_estado()

@estado.route('/consultar/estado/', methods=['GET'])
@cross_origin() 
def consultar_estado_nombre():
    return con_estado.consultar_estado_nombre()

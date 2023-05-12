from flask import Flask, jsonify, request, Blueprint
from flask_cors import cross_origin
from controllers.prestamoc import *

prestamo = Blueprint('prestamo', __name__)

con_prestamo = Prestamoc()

@prestamo.route('/prestamos', methods=['GET'])
@cross_origin() 
def consultar_prestamos():
    return con_prestamo.consultar_prestamos()

@prestamo.route('/consultar/prestamo', methods=['GET'])
@cross_origin() 
def consultar_prestamo():
    return con_prestamo.consultar_prestamo()

@prestamo.route('/insertar/prestamo', methods=['POST'])
@cross_origin() 
def insertar_prestamo():
    return con_prestamo.insertar_prestamo()

@prestamo.route('/editar/prestamo', methods=['PUT'])
@cross_origin() 
def editar_prestamo():
    return con_prestamo.editar_prestamo()

@prestamo.route('/eliminar/prestamo', methods=['DELETE'])
@cross_origin() 
def eliminar_prestamo():
    return con_prestamo.eliminar_prestamo()

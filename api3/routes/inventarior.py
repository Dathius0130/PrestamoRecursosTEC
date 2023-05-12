from flask import Flask, jsonify, request, Blueprint
from flask_cors import  cross_origin

from controllers.inventarioc import *

inventario = Blueprint('inventario', __name__)

con_inventario = Inventarioc()

@inventario.route('/inventario', methods=['GET'])
@cross_origin() 
def consultar_inventario():
    return con_inventario.consultar_inventario()

@inventario.route('/consultar/inventario/id', methods=['GET'])
@cross_origin() 
def consultar_consultar_id():
    return con_inventario.consultar_consultar_id()

@inventario.route('/insertar/inventario', methods=['POST'])
@cross_origin() 
def insertar_inventario():
    return con_inventario.insertar_inventario()

@inventario.route('/editar/inventario', methods=['POST'])
@cross_origin() 
def editar_inventario():
    return con_inventario.editar_inventario()


@inventario.route('/get/ultimo/inv', methods=['GET'])
@cross_origin() 
def ultima_fila():
    return con_inventario.ultima_fila()


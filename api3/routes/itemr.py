from flask import Flask, jsonify, request, Blueprint
from flask_cors import  cross_origin
from controllers.itemc import *

item = Blueprint('item', __name__)

con_item = Itemc()

@item.route('/items', methods=['GET'])
@cross_origin() 
def consultar_items():
    return con_item.consultar_items()

@item.route('/consultar/items/id', methods=['GET'])
@cross_origin() 
def consultar_item():
    return con_item.consultar_item()

@item.route('/insertar/item', methods=['POST'])
@cross_origin() 
def insertar_items():
    return con_item.insertar_items()

@item.route('/editar/item', methods=['PUT'])
@cross_origin() 
def editar_item():
    return con_item.editar_item()


"""This module stores the database details
   with the table definations """
import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from ItemCatlog_configPath import DBPATH
Base = declarative_base()


class User(Base):
    """This class stores the details of User"""
    __tablename__ = 'user'

    userName = Column(String(80), primary_key=True)
    userPassword = Column(String(250))
    userEmail = Column(String(250))


class Category(Base):
    """This class stores the details of Category"""
    __tablename__ = 'category'

    id = Column(Integer, primary_key=True)
    catName = Column(String(80), nullable=False)
    userName = Column(String(80), ForeignKey('user.userName'))
    user = relationship(User)

    """properties are serialized to disaply the
       Category details in JSON format"""
    @property
    def serialize(self):
        return{
            'id':   self.id,
            'catName':   self.catName,
            }


class Item(Base):
    """This class stores the details of Items"""
    __tablename__ = 'sub_category'

    itemName = Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)
    description = Column(String(250))
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)
    userName = Column(String(80), ForeignKey('user.userName'))
    user = relationship(User)

    """properties are serialized to disaply the
       Item details in JSON format"""
    @property
    def serialize(self):
        return{
                'cat_id':   self.category_id,
                'id':   self.id,
                'ItemName':    self.itemName,
                'description':   self.description,
            }


engine = create_engine('sqlite:///' + DBPATH)

Base.metadata.create_all(engine)

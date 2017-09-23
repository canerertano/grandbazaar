from sqlalchemy import Column, ForeignKey, String, Integer, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    email = Column(String(100), nullable=False)
    picture = Column(String(250))

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'picture': self.picture
        }


class Category(Base):
    __tablename__ = "category"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    owner_id = Column(Integer, ForeignKey("user.id"))
    owner = relationship(User)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'owner': self.owner.serialize
        }


class Item(Base):
    __tablename__ = "item"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    description = Column(String(250))
    picture = Column(String(250))
    price = Column(Float)
    category_id = Column(Integer, ForeignKey("category.id"))
    category = relationship(Category)
    owner_id = Column(Integer, ForeignKey("user.id"))
    owner = relationship(User)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'picture': self.picture,
            'price': self.price,
            'category': self.category.serialize,
            'owner': self.owner.serialize
        }

engine = create_engine('sqlite:///itemcatalog.db')

Base.metadata.create_all(engine)

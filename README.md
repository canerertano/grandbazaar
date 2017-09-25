# Udacity FSND Catalog Project

This project is my implementation of requested catalog project.
Without login users just see the items. Ones a user logged in with their Google account to the system, he/she can add catalogs and items, edit or delete them.
#### Technology stack contains;
* Python
* Flask Framework
* SQL Alchemy
* OAuth 2.0
* Html
* Javascript
* Css
* Bootstrap

## Instructions

1. Install Vagrant and VirtualBox
2. Clone the [fullstack-nanodegree-vm](http://github.com/udacity/fullstack-nanodegree-vm)
3. Clone this repository to the vagrant/catalog directory (which will automatically be synced to /vagrant/catalog within the VM).
4. Launch the Vagrant VM (vagrant up)
5. Run the application within the VM;
    ```sh
        $ python itemCatalog.py
    ```
6. Access and the application by visiting http://localhost:8000 locally

## RESTful API
There is a number of JSON endpoints which you can access with this URLs;
* GET API/categories
* GET API/categories/:category_id
* GET API/categories/:category_id/items
* GET API/categories/:category_id/items/:item_id
* GET API/items
* GET API/items/:id

## Author
Caner Ertano @cnrkfks

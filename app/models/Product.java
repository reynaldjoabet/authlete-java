package models;

public class Product {
    public static final io.ebean.Finder<Long, Product> find = new io.ebean.Finder<>(Product.class);

    public Long productId;
    public String productName;
    public String description;
    public Double price;

    public void save() {
        io.ebean.Ebean.save(this);
    }

    public void update() {
        io.ebean.Ebean.update(this);
    }

    public void delete() {
        io.ebean.Ebean.delete(this);
    }
}
(function() {
  var FObject;

  namespace("fragments", {
    FObject: FObject = (function() {

      function FObject(json, id) {
        this.json = json;
        this.id = id;
        this.rootDom = null;
        this.html = $('<div>').attr('id', this.id.toString());
      }

      FObject.prototype.setTitle = function() {
        return this.rootDom.append($('<h2>').append(this.json.title));
      };

      FObject.prototype.render = function(root) {
        if (root) {
          this.rootDom = root;
          if (this.json.title) this.setTitle(root);
          return this.rootDom.append(this.html);
        }
      };

      FObject.prototype.clear = function() {
        return this.rootDom.empty();
      };

      return FObject;

    })()
  });

}).call(this);

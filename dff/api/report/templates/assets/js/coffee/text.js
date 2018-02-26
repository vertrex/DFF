(function() {
  var TextFragment,
    __hasProp = Object.prototype.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor; child.__super__ = parent.prototype; return child; };

  namespace("fragments", {
    TextFragment: TextFragment = (function(_super) {

      __extends(TextFragment, _super);

      function TextFragment(fragment, id) {
        this.fragment = fragment;
        this.id = id;
        TextFragment.__super__.constructor.apply(this, arguments);
        this.html.append($('<p>').append(this.fragment.data));
      }

      TextFragment.prototype.render = function(root) {
        return TextFragment.__super__.render.apply(this, arguments);
      };

      return TextFragment;

    })(fragments.FObject)
  });

}).call(this);

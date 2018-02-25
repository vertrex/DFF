(function() {
  var Manager, chatFragment, detailTableFragment, node, nodeListFragment, tabFragment, tableFragment, textFragment;

  namespace("fragments", {
    Manager: Manager = (function() {

      function Manager() {
        this.fragments = new Array();
      }

      Manager.prototype.create = function(fragment) {
        var frag, id;
        if (fragment.widget) {
          id = Math.floor((Math.random() * 1000) + 1);
          switch (fragment.widget) {
            case "text":
              frag = new textFragment(fragment, id);
              break;
            case "table":
              frag = new tableFragment(fragment, id);
              break;
            case "detail_table":
              frag = new detailTableFragment(fragment, id);
              break;
            case "node_list":
              frag = new nodeListFragment(fragment, id);
              break;
            case "node":
              frag = new node(fragment, id);
              break;
            case "tab":
              frag = new tabFragment(fragment, id);
              break;
            case "chat":
              frag = new chatFragment(fragment, id);
              break;
            default:
              return false;
          }
          this.fragments.push(frag);
          return frag;
        } else {
          return false;
        }
      };

      Manager.prototype.renderAll = function(rootDom) {
        var frag, _i, _len, _ref, _results;
        _ref = this.fragments;
        _results = [];
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          frag = _ref[_i];
          _results.push(frag.render(rootDom));
        }
        return _results;
      };

      Manager.prototype.clearAll = function() {
        var f, _i, _len, _ref;
        _ref = this.fragments;
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          f = _ref[_i];
          f.clear();
        }
        return this.fragments = new Array();
      };

      return Manager;

    })()
  }, tableFragment = fragments.TableFragment, tabFragment = fragments.Tab, detailTableFragment = fragments.DetailTableFragment, nodeListFragment = fragments.NodeListFragment, textFragment = fragments.TextFragment, node = fragments.Node, chatFragment = fragments.ChatFragment);

}).call(this);

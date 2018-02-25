(function() {
  var __bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; };

  this.Page = (function() {

    function Page() {
      this.refreshFragments = __bind(this.refreshFragments, this);      this.script_count = $('script').length;
      this.fmanager = new fragments.Manager();
      this.db = null;
      this.spinner = new Spinner();
    }

    Page.prototype.cleanPreviousScripts = function() {
      var i, script, scripts, _len, _results;
      scripts = $('script');
      _results = [];
      for (i = 0, _len = scripts.length; i < _len; i++) {
        script = scripts[i];
        if (i >= this.script_count) {
          _results.push($(script).remove());
        } else {
          _results.push(void 0);
        }
      }
      return _results;
    };

    Page.prototype.loadScript = function(url) {

      var target = document.getElementsByTagName('body')[0];
      target.appendChild(this.spinner.spin().el);
      var script;
      this.db = url;
      script = document.createElement('script');
      script.type = 'text/javascript';

      if (script.readyState) {
        script.onreadystatechange = function() {
          var _ref;
          if ((_ref = script.readyState) === 'loaded' || _ref === 'complete') {
            script.onreadystatechange = null;
            return this.refreshFragments();
          }
        };
      } else {
        script.onload = this.refreshFragments;
      }
      script.src = url;
      return document.getElementsByTagName('head')[0].appendChild(script);
    };

    Page.prototype.refreshFragments = function() {
      var frag, frags, _i, _len;
      if (this.db) {
        frags = DFF_DB.getDatabase(this.db);
        this.fmanager.clearAll();
        for (_i = 0, _len = frags.length; _i < _len; _i++) {
          frag = frags[_i];
          this.fmanager.create(frag);
        }
        this.fmanager.renderAll($('div.span10#content'));
        this.spinner.stop();
        return ;
      }
    };

    Page.prototype.refresh = function(page) {
      this.cleanPreviousScripts();
      return this.loadScript(page.content);
    };

    return Page;

  })();

}).call(this);

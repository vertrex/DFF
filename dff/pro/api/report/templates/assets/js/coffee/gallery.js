(function() {
  var NodeGalleryFragment,
    __bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; },
    __hasProp = Object.prototype.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor; child.__super__ = parent.prototype; return child; };

  namespace("fragments", {
    NodeGalleryFragment: NodeGalleryFragment = (function(_super) {

      __extends(NodeGalleryFragment, _super);

      function NodeGalleryFragment(json, id) {
        this.json = json;
        this.id = id;
        this.render = __bind(this.render, this);
        NodeGalleryFragment.__super__.constructor.call(this, this.json, this.id);
        console.log(this.json.view);
        this.container = $('<div>').addClass('container');
        this.max_visible_pages = 6;
        this.visible_items = 14;
        this.current_page = 0;
      }

      NodeGalleryFragment.prototype.configurePagination = function() {
        this.pages = parseInt(this.json.data.length / this.visible_items);
        if (this.json.data.length % this.visible_items > 0) {
          this.pages = this.pages + 1;
        }
        this.pages = this.pages - 1;
        if (this.pages < 0) return this.pages = 0;
      };

      NodeGalleryFragment.prototype.pagination = function() {
        var div_pages, end, link, num, paginate, start, stop, ul,
          _this = this;
        $('div.row-fluid#pagination').remove();
        paginate = $('<div>').addClass("row-fluid").attr("id", "pagination");
        div_pages = $('<div>').addClass("pagination pagination-centered");
        ul = $('<ul>').attr("id", "pagination");
        start = this.current_page - (this.current_page % this.max_visible_pages);
        end = start + this.max_visible_pages;
        stop = end > this.pages ? this.pages : end;
        this.previous(ul);
        for (num = start; start <= stop ? num <= stop : num >= stop; start <= stop ? num++ : num--) {
          link = $('<a>').attr('href', '#').append(num + 1);
          link.bind('click', function(event) {
            _this.current_page = parseInt($(event.target).text()) - 1;
            return _this.refresh();
          });
          if (num === this.current_page) {
            ul.append($('<li>').addClass('active').append(link));
          } else {
            ul.append($('<li>').append(link));
          }
        }
        this.next(ul);
        div_pages.append(ul);
        paginate.append(div_pages);
        return this.container.append(paginate);
      };

      NodeGalleryFragment.prototype.next = function(ul) {
        var a, li,
          _this = this;
        li = $('<li>');
        a = $('<a>').attr("href", "#").append(">>");
        if (this.current_page === this.pages) {
          li.addClass('disabled');
        } else {
          a.bind('click', function(event) {
            _this.current_page = _this.current_page + 1;
            return _this.refresh();
          });
        }
        return ul.append(li.append(a));
      };

      NodeGalleryFragment.prototype.previous = function(ul) {
        var a, li,
          _this = this;
        li = $('<li>');
        a = $('<a>').attr("href", "#").append("<<");
        if (this.current_page === 0) {
          li.addClass('disabled');
        } else {
          a.bind('click', function(event) {
            _this.current_page = _this.current_page - 1;
            return _this.refresh();
          });
        }
        return ul.append(li.append(a));
      };

      NodeGalleryFragment.prototype.createGallery = function() {
        var data, end, img, li, sdata, start, stop, thumbnails, _i, _len;
        $('ul.thumbnails').remove();
        data = this.json.data;
        start = this.current_page * this.visible_items;
        start = this.current_page > 0 ? start + 1 : start;
        end = start + this.visible_items;
        stop = end > data.length ? data.length : end;
        sdata = data.slice(start, stop + 1 || 9e9);
        thumbnails = $('<ul>').addClass('thumbnails').append($('<div>').addClass("span").attr("style", "display: none;"));
        for (_i = 0, _len = sdata.length; _i < _len; _i++) {
          img = sdata[_i];
          li = $('<li>').addClass('span2').append($('<a>').addClass('thumbnail').attr('href', img.file).append($('<img>').attr('src', img.thumb).attr('style', 'width: 128px; height:128px;')));
          thumbnails.append(li);
        }
        return this.container.append(thumbnails);
      };

      NodeGalleryFragment.prototype.refresh = function() {
        this.configurePagination();
        this.createGallery();
        return this.pagination();
      };

      NodeGalleryFragment.prototype.render = function(rootDom) {
        NodeGalleryFragment.__super__.render.apply(this, arguments);
        return this.html.append(this.container);
      };

      return NodeGalleryFragment;

    })(fragments.FObject)
  });

}).call(this);
